/*
 * Copyright (c) DNS TAPIR
 */

package tapir

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/eclipse/paho.golang/paho"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/ryanuber/columnize"
	"github.com/spf13/viper"
)

func Chomp(s string) string {
	if len(s) > 0 && strings.HasSuffix(s, "\n") {
		return s[:len(s)-1]
	}
	return s
}

const (
	TapirPub uint8 = 1 << iota
	TapirSub
)

func NewMqttEngine(clientid string, pubsub uint8, lg *log.Logger) (*MqttEngine, error) {
	if pubsub == 0 {
		return nil, fmt.Errorf("either (or both) pub or sub support must be requested for MQTT Engine")
	}

	if clientid == "" {
		return nil, fmt.Errorf("MQTT client id not specified")
	}

	server := viper.GetString("mqtt.server")
	if server == "" {
		return nil, fmt.Errorf("MQTT server not specified in config")
	}

	topic := viper.GetString("mqtt.topic")
	if topic == "" {
		return nil, fmt.Errorf("MQTT topic not specified in config")
	}

	clientCertFile := viper.GetString("mqtt.clientcert")
	if clientCertFile == "" {
		return nil, fmt.Errorf("MQTT client cert file not specified in config")
	}

	clientKeyFile := viper.GetString("mqtt.clientkey")
	if clientKeyFile == "" {
		return nil, fmt.Errorf("MQTT client key file not specified in config")
	}

	cacertFile := viper.GetString("mqtt.cacert")
	if cacertFile == "" {
		return nil, fmt.Errorf("MQTT CA cert file not specified in config")
	}

	// Setup CA cert for validating the MQTT connection
	caCert, err := os.ReadFile(cacertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate in file %s: %w", cacertFile, err)
	}
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM([]byte(caCert))
	if !ok {
		return nil, fmt.Errorf("failed to parse CA certificate in file %s", cacertFile)
	}

	// Setup client cert/key for mTLS authentication
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate in file %s: %w", clientCertFile, err)
	}

	me := MqttEngine{
		Topic:         topic,
		Server:        server,
		ClientID:      clientid,
		ClientCert:    clientCert,
		CaCertPool:    caCertPool,
		ValidatorKeys: make(map[string]*ecdsa.PublicKey),
		MsgCounter:    make(map[string]uint32),
		MsgTimeStamp:  make(map[string]time.Time),
		Logger:        lg,
	}

	signingKeyFile := viper.GetString("mqtt.signingkey")
	if pubsub&TapirPub == 0 {
		lg.Printf("MQTT pub support not requested, only sub possible")
	} else if signingKeyFile == "" {
		lg.Printf("MQTT signing key file not specified in config, publish not possible")
	} else {
		signingKey, err := os.ReadFile(signingKeyFile)
		if err != nil {
			return nil, err
		}

		// Setup key used for creating the JWS
		pemBlock, _ := pem.Decode(signingKey)
		if pemBlock == nil || pemBlock.Type != "EC PRIVATE KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing private key")
		}
		me.PrivKey, err = x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		me.CanPublish = true
	}

	me.QoS = viper.GetInt("mqtt.qos")
	if me.QoS == 0 {
		fmt.Printf("MQTT subscribe quality-of-service not specified in config, using 0")
	}

	signingPubFile := viper.GetString("mqtt.validatorkey")
	if pubsub&TapirSub == 0 {
		lg.Printf("MQTT sub support not requested, only pub possible")
	} else if signingPubFile == "" {
		lg.Printf("MQTT validator pub file not specified in config, subscribe not possible")
	} else {
		signingPub, err := os.ReadFile(signingPubFile)
		if err != nil {
			return nil, err
		}

		// Setup key used for creating the JWS
		pemBlock, _ := pem.Decode(signingPub)
		if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing public key")
		}
		me.PubKey, err = x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key in file %s: %w", signingPubFile, err)
		}
		// log.Printf("PubKey is of type %t", me.PubKey)
		me.CanSubscribe = true
	}

	// Setup connection to the MQTT bus
	conn, err := tls.Dial("tcp", me.Server, &tls.Config{
		RootCAs:      me.CaCertPool,
		Certificates: []tls.Certificate{me.ClientCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dial MQTT server %s: %w", me.Server, err)
	}

	var tag string
	if me.CanPublish {
		tag += "PUB"
	}
	if me.CanSubscribe {
		tag += "SUB"
	}

	//	logger := log.New(os.Stdout, fmt.Sprintf("%s (%s): ", tag, me.ClientID), log.LstdFlags)

	me.MsgChan = make(chan *paho.Publish)

	c := paho.NewClient(paho.ClientConfig{
		// XXX: The router seems to only bee needed for subscribers
		Router: paho.NewStandardRouterWithDefault((func(m *paho.Publish) { me.MsgChan <- m })),
		// AutoReconnect: true,
		Conn: conn,
	})

	if GlobalCF.Debug {
		c.SetDebugLogger(lg)
	}
	c.SetErrorLogger(lg)

	me.Client = c

	me.CmdChan = make(chan MqttEngineCmd, 1)
	me.PublishChan = make(chan MqttPkg, 10)   // Here clients send us messages to pub
	me.SubscribeChan = make(chan MqttPkg, 10) // Here we send clients messages that arrived via sub

	StartEngine := func(resp chan MqttEngineResponse) {
		cp := &paho.Connect{
			KeepAlive:  30,
			ClientID:   me.ClientID,
			CleanStart: true,
		}

		ca, err := me.Client.Connect(context.Background(), cp)
		if err != nil {
			resp <- MqttEngineResponse{
				Error:    true,
				ErrorMsg: fmt.Sprintf("Error from mp.Client.Connect: %v", err),
			}
			return
		}
		if ca.ReasonCode != 0 {
			resp <- MqttEngineResponse{
				Error: true,
				ErrorMsg: fmt.Sprintf("Failed to connect to %s: %d - %s", me.Server,
					ca.ReasonCode, ca.Properties.ReasonString),
			}
			return
		}
		lg.Printf("Connected to %s\n", me.Server)

		if me.CanPublish {
			lg.Printf("Publishing on topic %s", me.Topic)
		}

		if me.CanSubscribe {
			subs := []paho.SubscribeOptions{}
			for topic := range me.ValidatorKeys {
				subs = append(subs, paho.SubscribeOptions{Topic: topic, QoS: byte(me.QoS)})
			}
			// log.Printf("MQTT Engine: there are %d topics to subscribe to", len(subs))
			for _, v := range subs {
				lg.Printf("MQTT Engine: subscribing to topic %s", v.Topic)
			}

			sa, err := me.Client.Subscribe(context.Background(), &paho.Subscribe{
				//				Subscriptions: []paho.SubscribeOptions{
				//					{Topic: me.Topic, QoS: byte(me.QoS)},
				//				},
				Subscriptions: subs,
			})
			if err != nil {
				resp <- MqttEngineResponse{
					Error:    true,
					ErrorMsg: fmt.Sprintf("Error from mp.Client.Subscribe: %v", err),
				}
				return
			}
			fmt.Println(string(sa.Reasons))
			if sa.Reasons[0] != byte(me.QoS) {
				resp <- MqttEngineResponse{
					Error: true,
					ErrorMsg: fmt.Sprintf("Failed to subscribe to topic: %s reasons: %d",
						me.Topic, sa.Reasons[0]),
				}
				return
			}
			lg.Printf("Subscribed to %s", me.Topic)
		}
		resp <- MqttEngineResponse{
			Error:  false,
			Status: "all ok",
		}
	}

	StopEngine := func(resp chan MqttEngineResponse) {
		if me.Client != nil {
			d := &paho.Disconnect{ReasonCode: 0}
			err := me.Client.Disconnect(d)
			if err != nil {
				resp <- MqttEngineResponse{
					Error:    true,
					ErrorMsg: err.Error(),
				}
			} else {
				resp <- MqttEngineResponse{
					Status: "connection to MQTT broker closed",
				}
			}
			lg.Printf("MQTT StopEngine: MQTT client disconnected from broker\n")
		} else {
			lg.Printf("MQTT StopEngine: no MQTT client, nothing to stop\n")
		}
	}

	go func() {
		buf := new(bytes.Buffer)
		jenc := json.NewEncoder(buf)

		for {
			select {
			case outbox := <-me.PublishChan:
				if !me.CanPublish {
					lg.Printf("Error: pub request but this engine is unable to publish messages")
					continue
				}

				switch outbox.Type {
				case "text":
					buf.Reset()
					_, err = buf.WriteString(outbox.Msg)
					if err != nil {
						lg.Printf("Error from buf.Writestring(): %v", err)
					}
					if GlobalCF.Debug {
						lg.Printf("MQTT Engine: received text msg: %s", outbox.Msg)
					}

				case "data":
					if GlobalCF.Debug {
						lg.Printf("MQTT Engine: received raw data: %v", outbox.Data)
					}
					buf.Reset()
					outbox.TimeStamp = time.Now()
					err = jenc.Encode(outbox.Data)
					if err != nil {
						lg.Printf("MQTT Engine: Error from json.NewEncoder: %v", err)
						continue
					}
				}

				sMsg, err := jws.Sign(buf.Bytes(), jws.WithJSON(), jws.WithKey(jwa.ES256, me.PrivKey))
				if err != nil {
					lg.Printf("MQTT Engine: failed to create JWS message: %s", err)
				}

				if _, err = me.Client.Publish(context.Background(), &paho.Publish{
					Topic:   me.Topic,
					Payload: sMsg,
				}); err != nil {
					lg.Printf("MQTT Engine: error sending message: %v", err)
					continue
				}
				if GlobalCF.Debug {
					lg.Printf("sent signed JWS: %s", string(sMsg))
				}

			case inbox := <-me.MsgChan:
				if GlobalCF.Debug {
					lg.Println("MQTT Engine: received message:", string(inbox.Payload))
				}
				pkg := MqttPkg{TimeStamp: time.Now(), Data: TapirMsg{}}
				log.Printf("MQTT Engine: topic: %v", inbox.Topic)
				me.MsgCounter[inbox.Topic]++
				me.MsgTimeStamp[inbox.Topic] = time.Now()
				validatorkey := me.ValidatorKeys[inbox.Topic]
				if validatorkey == nil {
					lg.Printf("MQTT Engine: Danger Will Robinson: validator key for MQTT topic %s not found. Dropping message.", inbox.Topic)
				} else {
					payload, err := jws.Verify(inbox.Payload, jws.WithKey(jwa.ES256, validatorkey))
					if err != nil {
						pkg.Error = true
						pkg.ErrorMsg = fmt.Sprintf("MQTT Engine: failed to verify message: %v", err)
						lg.Printf("MQTT Engine: failed to verify message: %v", err)
						// log.Printf("MQTT Engine: received msg: %v", string(inbox.Payload))
					} else {
						lg.Printf("MQTT Engine: verified message: %s", string(payload))
						r := bytes.NewReader(payload)
						err = json.NewDecoder(r).Decode(&pkg.Data)
						if err != nil {
							pkg.Error = true
							pkg.ErrorMsg = fmt.Sprintf("MQTT Engine: failed to decode json: %v", err)
						}
					}

					me.SubscribeChan <- pkg
				}

			case cmd := <-me.CmdChan:
				fmt.Printf("MQTT Engine: %s command received\n", cmd.Cmd)
				switch cmd.Cmd {
				case "stop":
					StopEngine(cmd.Resp)
				case "start":
					StartEngine(cmd.Resp)
				case "restart":
					StopEngine(cmd.Resp)
					StartEngine(cmd.Resp)
				default:
					lg.Printf("MQTT Engine: Error: unknown command: %s", cmd.Cmd)
				}
				fmt.Printf("MQTT Engine: cmd %s handled.\n", cmd.Cmd)
			}
		}
	}()

	return &me, nil
}

func (me *MqttEngine) AddTopic(topic string, validatorkey *ecdsa.PublicKey) error {
	//	log.Printf("MQTT Engine: AddTopic: topic %s, validatorkey %v", topic, validatorkey)
	if topic != "" && validatorkey != nil {
		// log.Printf("MQTT Engine: AddTopic: me: %v", me)
		me.ValidatorKeys[topic] = validatorkey
		log.Printf("MQTT Engine: added topic %s. Engine now has %d topics", topic, len(me.ValidatorKeys))
		return nil
	}
	return fmt.Errorf("invalid topic '%s' or validator key '%v'", topic, validatorkey)
}

func (me *MqttEngine) StartEngine() (chan MqttEngineCmd, chan MqttPkg, chan MqttPkg, error) {
	if len(me.ValidatorKeys) == 0 {
		return nil, nil, nil, fmt.Errorf("MQTT Engine: no topics added")
	}
	resp := make(chan MqttEngineResponse, 1)
	me.CmdChan <- MqttEngineCmd{Cmd: "start", Resp: resp}
	r := <-resp
	if r.Error {
		log.Printf("Error: error: %s", r.ErrorMsg)
		return me.CmdChan, me.PublishChan, me.SubscribeChan, fmt.Errorf(r.ErrorMsg)
	}
	return me.CmdChan, me.PublishChan, me.SubscribeChan, nil
}

func (me *MqttEngine) StopEngine() (chan MqttEngineCmd, error) {
	resp := make(chan MqttEngineResponse, 1)
	me.CmdChan <- MqttEngineCmd{Cmd: "stop", Resp: resp}
	r := <-resp
	if r.Error {
		log.Printf("Error: error: %s", r.ErrorMsg)
		return me.CmdChan, fmt.Errorf(r.ErrorMsg)
	}
	return me.CmdChan, nil
}

func (me *MqttEngine) RestartEngine() (chan MqttEngineCmd, error) {
	resp := make(chan MqttEngineResponse, 1)
	me.CmdChan <- MqttEngineCmd{Cmd: "restart", Resp: resp}
	r := <-resp
	if r.Error {
		log.Printf("Error: error: %s", r.ErrorMsg)
		return me.CmdChan, fmt.Errorf(r.ErrorMsg)
	}
	return me.CmdChan, nil
}

func (me *MqttEngine) Stats() MqttStats {
	return MqttStats{
		MsgCounter:   me.MsgCounter,
		MsgTimeStamp: me.MsgTimeStamp,
	}
}

// Trivial interrupt handler to catch SIGTERM and stop the MQTT engine nicely
func (me *MqttEngine) SetupInterruptHandler() {
	ic := make(chan os.Signal, 1)
	signal.Notify(ic, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range ic {
			fmt.Println("SIGTERM interrupt received, sending stop signal to MQTT Engine")
			me.StopEngine()
		}
	}()
}

// XXX: Only used for debugging
func SetupTapirMqttSubPrinter(inbox chan MqttPkg) {
	go func() {
		var pkg MqttPkg
		for pkg = range inbox {
			var out []string
			fmt.Printf("Received TAPIR MQTT Message:\n")
			for _, a := range pkg.Data.Added {
				out = append(out, fmt.Sprintf("ADD: %s|%032b", a.Name, a.TagMask))
			}
			for _, a := range pkg.Data.Removed {
				out = append(out, fmt.Sprintf("DEL: %s", a.Name))
			}
			fmt.Println(columnize.SimpleFormat(out))
		}
	}()
}

// XXX: Only used for debugging
func PrintTapirMqttPkg(pkg MqttPkg, lg *log.Logger) {
	var out []string
	lg.Printf("Received TAPIR MQTT Message:\n")
	for _, a := range pkg.Data.Added {
		out = append(out, fmt.Sprintf("ADD: %s|%032b", a.Name, a.TagMask))
	}
	for _, a := range pkg.Data.Removed {
		out = append(out, fmt.Sprintf("DEL: %s", a.Name))
	}
	lg.Println(columnize.SimpleFormat(out))
}

func FetchMqttValidatorKey(topic, filename string) (*ecdsa.PublicKey, error) {
	log.Printf("FetchMqttValidatorKey: topic %s, filename %s", topic, filename)
	var PubKey *ecdsa.PublicKey
	if filename == "" {
		log.Printf("MQTT validator validator key for topic %s file not specified in config, subscribe not possible", topic)
	} else {
		signingPub, err := os.ReadFile(filename)
		if err != nil {
			log.Printf("MQTT validator validator key for topic %s: failed to read file %s: %v", topic, filename, err)
			return nil, err
		}

		// Setup key used for creating the JWS
		pemBlock, _ := pem.Decode(signingPub)
		if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing public key")
		}
		tmp, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			log.Printf("MQTT validator validator key for topic %s: failed to parse key: %v", topic, err)
			return nil, err
		}
		PubKey = tmp.(*ecdsa.PublicKey)
	}
	return PubKey, nil
}
