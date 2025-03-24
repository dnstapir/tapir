/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tapir

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
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
	"github.com/gookit/goutil/dump"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
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

func NewMqttEngine(creator, clientid string, pubsub uint8, statusch chan ComponentStatusUpdate, lg *log.Logger) (*MqttEngine, error) {
	if pubsub == 0 {
		return nil, fmt.Errorf("either (or both) pub or sub support must be requested for MQTT Engine")
	}

	if clientid == "" {
		return nil, fmt.Errorf("MQTT client id not specified")
	}

	server := viper.GetString("tapir.mqtt.server")
	if server == "" {
		return nil, fmt.Errorf("MQTT server not specified in config")
	}

	qos := viper.GetInt("tapir.mqtt.qos")
	if qos == 0 {
		fmt.Printf("MQTT subscribe quality-of-service not specified in config, using 2")
		qos = 2
	}

	keystoreFilename := viper.GetString("keystore.path")
	if keystoreFilename == "" {
		return nil, fmt.Errorf("MQTT validation key storage not specified!")
	}

	keystore, err := jwk.ReadFile(keystoreFilename)
	if err != nil {
		return nil, fmt.Errorf("Error reading keystorage file!")
	}

	_, caCertPool, clientCert, err := FetchTapirClientCert(lg, statusch)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client certificate: %w", err)
	}

	me := MqttEngine{
		Server:       server,
		Creator:      creator,
		ClientID:     clientid,
		ClientCert:   *clientCert,
		CaCertPool:   caCertPool,
		TopicData:    make(map[string]TopicData),
		PrefixTopics: make(map[string]bool),
		Logger:       lg,
		QoS:          qos,
		Keystore:     keystore,
	}

	if pubsub&TapirPub == 0 {
		lg.Printf("MQTT pub support not requested, only sub possible")
	} else {
		me.CanPublish = true
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
	me.PublishChan = make(chan MqttPkgOut, 10)  // Here clients send us messages to pub
	me.SubscribeChan = make(chan MqttPkgIn, 10) // Here we send clients messages that arrived via sub

	StartEngine := func(resp chan MqttEngineResponse) error {
		var ctx context.Context
		// me.Cancel is used to tell the paho connection manager to stop
		ctx, me.Cancel = context.WithCancel(context.Background())

		var subs []paho.SubscribeOptions
		if me.CanSubscribe {
			nolocal := false
			for topic, data := range me.TopicData {
				// if data.ValidatorKey != nil {
				if data.SubMode != "" {
					lg.Printf("MQTT Engine: subscribing to topic %s with mode %s, qos: %d", topic, data.SubMode, me.QoS)
					subs = append(subs, paho.SubscribeOptions{Topic: topic, QoS: byte(me.QoS), NoLocal: nolocal})
				}
			}

			// log.Printf("MQTT Engine: there are %d topics to subscribe to", len(subs))
			// for _, v := range subs {
			// 	lg.Printf("MQTT Engine: subscribing to topic %s", v.Topic)
			// }
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
				lg.Printf("MQTT Engine %s: MQTT connection up", me.Creator)
				if subs != nil {
					lg.Printf("MQTT Engine %s: subscribing to topics: %v", me.Creator, subs)
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
						// lg.Printf("received message on topic %s; body: %s (retain: %t)\n", pr.Packet.Topic, pr.Packet.Payload, pr.Packet.Retain)
						me.MsgChan <- pr
						return true, nil
					},
				},
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

		lg.Printf("MQTT Engine %s: Connected to %s\n", me.Creator, me.Server)

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
					lg.Printf("MQTT Engine %s: Error: pub request but this engine is unable to publish messages", me.Creator)
					continue
				}

				lg.Printf("MQTT Engine %s: will publish message on topic: %s", me.Creator, outbox.Topic)
				switch outbox.Type {
				case "text":
					buf.Reset()
					_, err = buf.WriteString(outbox.Msg)
					if err != nil {
						lg.Printf("Error from buf.Writestring(): %v", err)
					}
					if GlobalCF.Debug {
						lg.Printf("MQTT Engine %s: received text msg: %s", me.Creator, outbox.Msg)
					}

				case "data":
					if GlobalCF.Debug {
						lg.Printf("MQTT Engine %s: received data: %+v", me.Creator, outbox.Data)
					}
					buf.Reset()
					outbox.TimeStamp = time.Now()
					err = jenc.Encode(outbox.Data)
					if err != nil {
						lg.Printf("MQTT Engine %s: Error from json.NewEncoder: %v", me.Creator, err)
						continue
					}

				case "raw":
					if GlobalCF.Debug {
						lg.Printf("MQTT Engine %s: received raw data: %+v", me.Creator, outbox.RawData)
					}
					buf.Reset()
					outbox.TimeStamp = time.Now()
					err = jenc.Encode(outbox.RawData)
					if err != nil {
						lg.Printf("MQTT Engine %s: Error from json.NewEncoder: %v", me.Creator, err)
						continue
					}

				default:
					lg.Printf("MQTT Engine: unknown outbox message type: %s. Ignoring message.", outbox.Type)
					continue
				}

				var payload []byte
				td := me.TopicData[outbox.Topic]
				// signingkey := me.SigningKeys[outbox.Topic]
				if td.Sign {
					lg.Printf("MQTT Engine %s: signing message on topic %s", me.Creator, outbox.Topic)
					signingkey := td.SigningKey
					if signingkey == nil {
						lg.Printf("MQTT Engine %s: Danger Will Robinson: signing key for MQTT topic %s not found. Dropping message.",
							me.Creator, outbox.Topic)
						continue
					}

					payload, err = jws.Sign(buf.Bytes(), jws.WithJSON(), jws.WithKey(jwa.ES256, signingkey))
					if err != nil {
						lg.Printf("MQTT Engine %s: failed to create JWS message: %s", me.Creator, err)
						continue
					}
				} else {
					payload = buf.Bytes()
					lg.Printf("MQTT Engine %s: not signing raw message being sent to topic %s", me.Creator, outbox.Topic)
				}

				mqttMsg := paho.Publish{
					Topic:   outbox.Topic,
					Payload: payload,
					QoS:     byte(me.QoS),
					Retain:  outbox.Retain,
				}
				pubresponse, err := me.ConnectionManager.Publish(context.Background(), &mqttMsg)
				if err != nil {
					lg.Printf("MQTT Engine %s: error sending message: %v", me.Creator, err)
					continue
				}

				fmt.Printf("MQTT Engine %s: publish qos: %d, response: %+v\n", me.Creator, me.QoS, pubresponse)
				dump.P(pubresponse)

				td.PubMsgs++
				td.LatestPub = time.Now()
				me.TopicData[outbox.Topic] = td
				if GlobalCF.Debug {
					lg.Printf("MQTT Engine %s: sent message on topic %s: %s", me.Creator, outbox.Topic, string(payload))
				}

			case inbox := <-me.MsgChan:
				if GlobalCF.Debug {
					// lg.Printf("MQTT Engine %s: received message: %s", me.Creator, string(inbox.Packet.Payload))
				}

				lg.Printf("MQTT Engine %s: received message on topic: %v", me.Creator, inbox.Packet.Topic)

				// td := me.TopicData[inbox.Packet.Topic]
				td, err := me.FetchTopicData(inbox.Packet.Topic)
				if err != nil {
					lg.Printf("MQTT Engine %s: error fetching topic data for topic %s: %v", me.Creator, inbox.Packet.Topic, err)
					continue
				}
				td.SubMsgs++
				td.LatestSub = time.Now()
				me.TopicData[td.Topic] = td

				mpi := MqttPkgIn{
					TimeStamp: time.Now(),
					Topic:     inbox.Packet.Topic,
					Payload:   inbox.Packet.Payload,
					Validated: false,
				}

				if td.Validate {
					payload, err := jws.Verify(inbox.Packet.Payload, jws.WithKeySet(me.Keystore))
					if err != nil {
						mpi.Error = true
						mpi.ErrorMsg = fmt.Sprintf("MQTT Engine %s: failed to verify message: %v", me.Creator, err)
						lg.Printf("MQTT Engine %s: failed to verify message: %v", me.Creator, err)
						// log.Printf("MQTT Engine: received msg: %v", string(inbox.Payload))
						continue
					}
					lg.Printf("MQTT Engine %s: successfully verified message on topic %s", me.Creator, inbox.Packet.Topic)

					mpi.Validated = true
					mpi.Payload = payload
				} else {
					lg.Printf("MQTT Engine %s: unvalidated message: %s", me.Creator, inbox.Packet.Payload)
				}
				lg.Printf("MQTT Engine td.SubscriberCh: %+v", td.SubscriberCh)
				if td.SubscriberCh != nil {
					td.SubscriberCh <- mpi
				} else {
					lg.Printf("MQTT Engine %s: no subscriber channel for topic %s. Dropping message.", me.Creator, inbox.Packet.Topic)
				}
				lg.Printf("MQTT Engine %s: incoming message send to recipient via channel. All done.", me.Creator)

			case cmd := <-me.CmdChan:
				fmt.Printf("MQTT Engine %s: %s command received\n", me.Creator, cmd.Cmd)
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
				fmt.Printf("MQTT Engine %s: cmd %s handled.\n", me.Creator, cmd.Cmd)
			}
		}
	}()

	return &me, nil
}

func (me *MqttEngine) PubToTopic(topic string, signingkey *ecdsa.PrivateKey, mode string, sign bool) (map[string]TopicData, error) {
	if topic == "" {
		return me.TopicData, fmt.Errorf("PubToTopic: topic not specified")
	}
	if signingkey == nil && sign {
		return me.TopicData, fmt.Errorf("PubToTopic: no signing key specified and signing requested")
	}

	if mode != "raw" && mode != "struct" {
		return me.TopicData, fmt.Errorf("PubToTopic: unknown mode: %s", mode)
	}

	if _, exist := me.TopicData[topic]; !exist {
		me.TopicData[topic] = TopicData{}
	}
	tdata := me.TopicData[topic]

	tdata.PubMode = mode
	tdata.Sign = sign

	if signingkey != nil {
		tdata.SigningKey = signingkey
		log.Printf("MQTT Engine %s: added signingkey for topic %s.", me.Creator, topic)
	}

	me.TopicData[topic] = tdata

	log.Printf("MQTT Engine %s: added pub topic %s. Engine now has %d topics", me.Creator, topic, len(me.TopicData))

	// does the MqttEngine already have a connection manager (i.e. is it already running)
	if me.ConnectionManager != nil {
		if _, err := me.ConnectionManager.Subscribe(context.Background(), &paho.Subscribe{
			Subscriptions: []paho.SubscribeOptions{
				{
					Topic: topic,
					QoS:   byte(me.QoS),
				},
			},
		}); err != nil {
			return me.TopicData, fmt.Errorf("AddTopic: failed to subscribe to topic %s: %v", topic, err)
		}
		log.Printf("MQTT Engine %s: added topic %s to running MQTT Engine. Engine now has %d topics", me.Creator, topic, len(me.TopicData))
	}

	return me.TopicData, nil
}

func (me *MqttEngine) SubToTopic(topic string,
	subscriberCh chan MqttPkgIn, mode string, validate bool,
) (map[string]TopicData, error) {
	log.Printf("MQTT Engine: SubToTopic: topic %s, subscriberCh %v, mode %s, validate %t", topic, subscriberCh, mode, validate)
	if topic == "" {
		return me.TopicData, fmt.Errorf("SubToTopic: topic not specified")
	}

	if mode != "raw" && mode != "struct" {
		return me.TopicData, fmt.Errorf("SubToTopic: unknown mode: %s", mode)
	}

	if subscriberCh == nil {
		return me.TopicData, fmt.Errorf("SubToTopic: subscriber channel not specified")
	}

	if strings.HasSuffix(topic, "/#") {
		me.PrefixTopics[strings.TrimSuffix(topic, "#")] = true
	}

	if _, exist := me.TopicData[topic]; !exist {
		me.TopicData[topic] = TopicData{
			Topic: topic,
		}
	}
	tdata := me.TopicData[topic]

	tdata.SubMode = mode
	tdata.Validate = validate
	tdata.SubscriberCh = subscriberCh

	me.TopicData[topic] = tdata
	log.Printf("MQTT Engine %s: added sub topic %s (validate %t, mode %s). Engine now has %d topics", me.Creator, topic, validate, mode, len(me.TopicData))

	// does the MqttEngine already have a connection manager (i.e. is it already running)
	if me.ConnectionManager != nil {
		if _, err := me.ConnectionManager.Subscribe(context.Background(), &paho.Subscribe{
			Subscriptions: []paho.SubscribeOptions{
				{
					Topic: topic,
					QoS:   byte(me.QoS),
				},
			},
		}); err != nil {
			return me.TopicData, fmt.Errorf("SubToTopic: failed to subscribe to topic %s: %v", topic, err)
		}
		var topics, prefixTopics []string
		for t := range me.TopicData {
			topics = append(topics, t)
		}
		for t := range me.PrefixTopics {
			prefixTopics = append(prefixTopics, t)
		}
		log.Printf("MQTT Engine %s: added sub topic %s to running MQTT Engine.", me.Creator, topic)
		log.Printf("Engine now has %d topics: %v and %d prefix topics: %v", len(me.TopicData), topics, len(me.PrefixTopics), prefixTopics)
	}

	log.Printf("MQTT Engine %s: TopicData for topic %s: %+v", me.Creator, topic, me.TopicData[topic])

	return me.TopicData, nil
}

func (me *MqttEngine) RemoveTopic(topic string) (map[string]TopicData, error) {
	if me.ConnectionManager != nil {
		if _, err := me.ConnectionManager.Unsubscribe(context.Background(), &paho.Unsubscribe{
			Topics: []string{topic},
		}); err != nil {
			return me.TopicData, fmt.Errorf("RemoveTopic: failed to unsubscribe from topic %s: %v", topic, err)
		}
	}
	// delete(me.SigningKeys, topic)
	// delete(me.ValidatorKeys, topic)
	delete(me.TopicData, topic)
	log.Printf("MQTT Engine: removed topic %s. Engine now has %d topics", topic, len(me.TopicData))
	return me.TopicData, nil
}

func (me *MqttEngine) StartEngine() (chan MqttEngineCmd, chan MqttPkgOut, chan MqttPkgIn, error) {
	// We can start the mqtt engine without topics, topics may be added later
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

func (me *MqttEngine) Stats() map[string]TopicData {
	//	return MqttStats{
	//		MsgCounters:   me.MsgCounters,
	//		MsgTimeStamps: me.MsgTimeStamps,
	//	}
	return me.TopicData
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

func (me *MqttEngine) FetchTopicData(topic string) (TopicData, error) {
	if td, exist := me.TopicData[topic]; exist {
		log.Printf("MQTT Engine %s: topic %s: exact match found. TopicData: %+v", me.Creator, topic, td)
		return td, nil
	}
	for prefix := range me.PrefixTopics {
		if strings.HasPrefix(topic, prefix) {
			log.Printf("MQTT Engine %s: topic %s matches prefix %s. TopicData: %+v", me.Creator, topic, prefix, me.TopicData[prefix])
			return me.TopicData[prefix+"#"], nil
		}
	}
	return TopicData{}, fmt.Errorf("FetchTopicData: topic %s not found", topic)
}

// XXX: Only used for debugging
func SetupTapirMqttSubPrinter(inbox chan MqttPkgIn) {
	go func() {
		var pkg MqttPkgIn
		for pkg = range inbox {
			var tm TapirMsg
			err := json.Unmarshal(pkg.Payload, &tm)
			if err != nil {
				fmt.Printf("MQTT: failed to decode json: %v", err)
				continue
			}
			var out []string
			fmt.Printf("Received TAPIR MQTT Message:\n")
			for _, a := range tm.Added {
				out = append(out, fmt.Sprintf("ADD: %s|%032b", a.Name, a.TagMask))
			}
			for _, a := range tm.Removed {
				out = append(out, fmt.Sprintf("DEL: %s", a.Name))
			}
			fmt.Println(columnize.SimpleFormat(out))
		}
	}()
}

// XXX: Only used for debugging
func PrintTapirMqttPkg(pkg MqttPkgIn, lg *log.Logger) {
	var tm TapirMsg
	err := json.Unmarshal(pkg.Payload, &tm)
	if err != nil {
		fmt.Printf("MQTT: failed to decode json: %v", err)
		return
	}

	PrintTapirMsg(tm, lg)
}

func PrintTapirMsg(tm TapirMsg, lg *log.Logger) {
	var out []string
	lg.Printf("Received TAPIR MQTT Message:\n")
	for _, a := range tm.Added {
		out = append(out, fmt.Sprintf("ADD: %s|%032b", a.Name, a.TagMask))
	}
	for _, a := range tm.Removed {
		out = append(out, fmt.Sprintf("DEL: %s", a.Name))
	}
	lg.Println(columnize.SimpleFormat(out))
}

func FetchMqttSigningKey(topic, filename string) (*ecdsa.PrivateKey, error) {
	log.Printf("FetchMqttSigningKey: topic %s, filename %s", topic, filename)
	var PrivKey ecdsa.PrivateKey
	if filename == "" {
		log.Printf("MQTT signing private key for topic %s file not specified in config, publish not possible", topic)
	} else {
		filename = filepath.Clean(filename)
		keyFile, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("Error reading signing key file")
		}

		keyParsed, err := jwk.ParseKey(keyFile)
		if err != nil {
			return nil, fmt.Errorf("Error parsing signing key file")
		}

		err = keyParsed.Raw(&PrivKey)
		if err != nil {
			return nil, fmt.Errorf("Error getting raw key from JWK")
		}
	}

	return &PrivKey, nil
}

// MqttTopic returns the MQTT topic for a given common name and viper key.
// The raw topic is something like "status/up/{EdgeId}/tapir-pop" and is specified in the tapir-pop.yaml
// config file. The common name is the common name of the TAPIR Edge cert.
func MqttTopic(commonName string, viperkey string) (string, error) {
	if viperkey == "" {
		return "", fmt.Errorf("MQTT topic viperkey not specified")
	}
	rawtopic := viper.GetString(viperkey)
	if rawtopic == "" {
		return "", fmt.Errorf("MQTT topic not specified in config")
	}
	topic := strings.Replace(rawtopic, "{EdgeId}", commonName, -1)
	return topic, nil
}
