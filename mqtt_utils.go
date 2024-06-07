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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
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
	cacertFile = filepath.Clean(cacertFile)
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
		Topic:         viper.GetString("mqtt.topic"),
		Server:        server,
		ClientID:      clientid,
		ClientCert:    clientCert,
		CaCertPool:    caCertPool,
		ValidatorKeys: make(map[string]*ecdsa.PublicKey),
		MsgCounters:   make(map[string]uint32),
		MsgTimeStamps: make(map[string]time.Time),
		Logger:        lg,
	}

	signingKeyFile := viper.GetString("mqtt.signingkey")
	if pubsub&TapirPub == 0 {
		lg.Printf("MQTT pub support not requested, only sub possible")
	} else if signingKeyFile == "" {
		lg.Printf("MQTT signing key file not specified in config, publish not possible")
	} else {
		signingKeyFile = filepath.Clean(signingKeyFile)
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

	if pubsub&TapirSub == 0 {
		lg.Printf("MQTT sub support not requested, only pub possible")
	} else {
		me.CanSubscribe = true
	}

	serverURL, err := url.Parse(me.Server)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MQTT server URL %s: %w", me.Server, err)
	}

	me.MsgChan = make(chan paho.PublishReceived)
	me.CmdChan = make(chan MqttEngineCmd, 1)
	me.PublishChan = make(chan MqttPkg, 10)   // Here clients send us messages to pub
	me.SubscribeChan = make(chan MqttPkg, 10) // Here we send clients messages that arrived via sub

	StartEngine := func(resp chan MqttEngineResponse) error {
		var ctx context.Context
		// me.Cancel is used to tell the paho connection manager to stop
		ctx, me.Cancel = context.WithCancel(context.Background())

		var subs []paho.SubscribeOptions
		if me.CanSubscribe {
			for topic := range me.ValidatorKeys {
				subs = append(subs, paho.SubscribeOptions{Topic: topic, QoS: byte(me.QoS)})
			}

			// log.Printf("MQTT Engine: there are %d topics to subscribe to", len(subs))
			for _, v := range subs {
				lg.Printf("MQTT Engine: subscribing to topic %s", v.Topic)
			}
		}

		apcConfig := autopaho.ClientConfig{
			ServerUrls: []*url.URL{serverURL},
			TlsCfg: &tls.Config{
				RootCAs:      me.CaCertPool,
				Certificates: []tls.Certificate{me.ClientCert},
				MinVersion:   tls.VersionTLS13,
			},
			KeepAlive:                     20,
			CleanStartOnInitialConnection: false,
			SessionExpiryInterval:         60,
			OnConnectionUp: func(cm *autopaho.ConnectionManager, connAck *paho.Connack) {
				lg.Println("MQTT Engine: MQTT connection up")
				if subs != nil {
					sa, err := cm.Subscribe(context.Background(), &paho.Subscribe{
						Subscriptions: subs,
					})
					if err != nil {
						resp <- MqttEngineResponse{
							Error:    true,
							ErrorMsg: fmt.Sprintf("Error from cm.Subscribe: %v", err),
						}

						return
					}

					lg.Println(string(sa.Reasons))
					if sa.Reasons[0] != byte(me.QoS) {
						topics := []string{}
						for _, sub := range subs {
							topics = append(topics, sub.Topic)
						}
						resp <- MqttEngineResponse{
							Error: true,
							ErrorMsg: fmt.Sprintf("Did not get expected QoS level when subscribing to topics %s reasons: %d",
								topics, sa.Reasons[0]),
						}
						return
					}
					lg.Println("mqtt subscription successful")
				}
			},
			Errors:         lg,
			PahoErrors:     lg,
			OnConnectError: func(err error) { lg.Printf("error whilst attempting connection: %s\n", err) },
			ClientConfig: paho.ClientConfig{
				ClientID: me.ClientID,
				OnPublishReceived: []func(paho.PublishReceived) (bool, error){
					func(pr paho.PublishReceived) (bool, error) {
						lg.Printf("received message on topic %s; body: %s (retain: %t)\n", pr.Packet.Topic, pr.Packet.Payload, pr.Packet.Retain)
						me.MsgChan <- pr
						return true, nil
					}},
				OnClientError: func(err error) { lg.Printf("client error: %s\n", err) },
				OnServerDisconnect: func(d *paho.Disconnect) {
					if d.Properties != nil {
						lg.Printf("server requested disconnect: %s\n", d.Properties.ReasonString)
					} else {
						lg.Printf("server requested disconnect; reason code: %d\n", d.ReasonCode)
					}
				},
			},
		}

		if GlobalCF.Debug {
			apcConfig.Debug = lg
			apcConfig.PahoDebug = lg
		}

		cm, err := autopaho.NewConnection(ctx, apcConfig)
		if err != nil {
			resp <- MqttEngineResponse{
				Error:    true,
				ErrorMsg: fmt.Sprintf("failed to create MQTT connection %s: %v", me.Server, err),
			}
			return err
		}

		me.ConnectionManager = cm

		if err = cm.AwaitConnection(ctx); err != nil {
			resp <- MqttEngineResponse{
				Error:    true,
				ErrorMsg: fmt.Sprintf("failed to wait for MQTT connection %s: %v", me.Server, err),
			}
			return err
		}

		lg.Printf("Connected to %s\n", me.Server)

		if me.CanPublish {
			if me.Topic == "" {
				return fmt.Errorf("MQTT topic for PUB not specified in config")
			}
			lg.Printf("Publishing on topic %s", me.Topic)
		}

		resp <- MqttEngineResponse{
			Error:  false,
			Status: "all ok",
		}
		return nil
	}

	StopEngine := func(resp chan MqttEngineResponse) {
		if me.ConnectionManager != nil {
			me.Cancel()

			lg.Printf("MQTT StopEngine: waiting for connection manager to stop")
			<-me.ConnectionManager.Done()

			resp <- MqttEngineResponse{
				Status: "connection to MQTT broker closed",
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

				if _, err = me.ConnectionManager.Publish(context.Background(), &paho.Publish{
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
					lg.Println("MQTT Engine: received message:", string(inbox.Packet.Payload))
				}
				pkg := MqttPkg{TimeStamp: time.Now(), Data: TapirMsg{}}
				log.Printf("MQTT Engine: topic: %v", inbox.Packet.Topic)
				me.MsgCounters[inbox.Packet.Topic]++
				me.MsgTimeStamps[inbox.Packet.Topic] = time.Now()
				validatorkey := me.ValidatorKeys[inbox.Packet.Topic]
				if validatorkey == nil {
					lg.Printf("MQTT Engine: Danger Will Robinson: validator key for MQTT topic %s not found. Dropping message.", inbox.Packet.Topic)
				} else {
					payload, err := jws.Verify(inbox.Packet.Payload, jws.WithKey(jwa.ES256, validatorkey))
					if err != nil {
						pkg.Error = true
						pkg.ErrorMsg = fmt.Sprintf("MQTT Engine: failed to verify message: %v", err)
						lg.Printf("MQTT Engine: failed to verify message: %v", err)
						// log.Printf("MQTT Engine: received msg: %v", string(inbox.Payload))
					} else {
						lg.Printf("MQTT Engine: verified message: %s", string(payload))
						r := bytes.NewReader(payload)
						pkg.Topic = inbox.Packet.Topic
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
		MsgCounters:   me.MsgCounters,
		MsgTimeStamps: me.MsgTimeStamps,
	}
}

// Trivial interrupt handler to catch SIGTERM and stop the MQTT engine nicely
func (me *MqttEngine) SetupInterruptHandler() {
	ic := make(chan os.Signal, 1)
	signal.Notify(ic, os.Interrupt, syscall.SIGTERM)
	go func() {
		for range ic {
			fmt.Println("SIGTERM interrupt received, sending stop signal to MQTT Engine")
			_, err := me.StopEngine()
			if err != nil {
				fmt.Printf("StopEngine failed: %v", err)
			}
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
		log.Printf("MQTT validator public key for topic %s file not specified in config, subscribe not possible", topic)
	} else {
		filename = filepath.Clean(filename)
		signingPub, err := os.ReadFile(filename)
		if err != nil {
			log.Printf("MQTT validator public key for topic %s: failed to read file %s: %v", topic, filename, err)
			return nil, err
		}

		// Setup key used for creating the JWS
		pemBlock, _ := pem.Decode(signingPub)
		if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing public key")
		}
		tmp, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			log.Printf("MQTT validator public key for topic %s: failed to parse key: %v", topic, err)
			return nil, err
		}
		PubKey = tmp.(*ecdsa.PublicKey)
	}
	return PubKey, nil
}
