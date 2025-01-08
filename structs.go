/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tapir

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"time"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"github.com/miekg/dns"
	"github.com/smhanov/dawg"
	// "your_project_path/tapirpb" // Adjust this import path to the actual path where your generated protobuf files are located
)

type ZoneType uint8

const (
	XfrZone ZoneType = iota
	MapZone
	SliceZone
	RpzZone
)

var ZoneTypeToString = map[ZoneType]string{
	XfrZone:   "xfr",
	MapZone:   "map",
	SliceZone: "slice",
	RpzZone:   "rpz",
}

type ZoneData struct {
	ZoneName   string
	ZoneType   ZoneType // 1 = "xfr", 2 = "map", 3 = "slice". An xfr zone only supports xfr related ops
	Owners     Owners
	OwnerIndex map[string]int
	ApexLen    int // # RRs that are stored separately
	SOA        dns.SOA
	NSrrs      []dns.RR // apex NS RRs

	// Rest of zone
	BodyRRs RRArray
	RRs     RRArray // BodyRRs + ApexRRs

	// Data		map[string]map[uint16][]dns.RR	// map[owner]map[rrtype][]dns.RR
	Data   map[string]OwnerData // map[owner]map[rrtype][]dns.RR
	RpzMap map[string]*RpzName  // map[owner]map[rrtype][]dns.RR

	// Other stuff
	DroppedRRs     int
	KeptRRs        int
	XfrType        string // axfr | ixfr
	Logger         *log.Logger
	IncomingSerial uint32
	//	RRKeepFunc     func(uint16) bool
	RRParseFunc func(*dns.RR, *ZoneData) bool
	Verbose     bool
	Debug       bool
	// RpzData        map[string]string // map[ownername]action. owner w/o rpz zone name
}

type Owners []OwnerData

type OwnerData struct {
	Name    string
	RRtypes map[uint16]RRset
}

type RRset struct {
	RRs []dns.RR
}

type CommandPost struct {
	Command   string
	Zone      string
	Name      string // Domain name to add/remove an RPZ action for
	ListType  string
	ListName  string // used in the export-doubtlist command
	Policy    string // RPZ policy
	Action    string // RPZ action (OBE)
	RpzSource string // corresponds with the sourceid in tem.yaml
}

type CommandResponse struct {
	Time                time.Time
	Status              string
	Zone                string
	Serial              uint32
	Data                []byte
	Msg                 string
	TapirFunctionStatus TapirFunctionStatus
	Error               bool
	ErrorMsg            string
}

type SloggerCmdPost struct {
	Command string
}

type SloggerCmdResponse struct {
	Time time.Time
	// TapirFunctionStatus TapirFunctionStatus
	PopStatus map[string]TapirFunctionStatus
	EdmStatus map[string]TapirFunctionStatus
	Msg       string
	Error     bool
	ErrorMsg  string
}

type BootstrapPost struct {
	Command  string
	ListName string
	Encoding string
}

type BootstrapResponse struct {
	Time   time.Time
	Status string
	Msg    string
	// MsgCounters   map[string]uint32    // map[topic]counter
	// MsgTimeStamps map[string]time.Time // map[topic]timestamp
	TopicData map[string]TopicData
	Error     bool
	ErrorMsg  string
}

type DebugPost struct {
	Command   string
	Zone      string
	Qname     string
	Qtype     uint16
	Component string
	Status    ComponentStatus
}

type DebugResponse struct {
	Time   time.Time
	Status string
	Zone   string
	//	ZoneData   ZoneData
	OwnerIndex       map[string]int
	RRset            RRset
	Lists            map[string]map[string]*WBGlist
	Allowlists       map[string]*WBGlist
	Denylists       map[string]*WBGlist
	Doubtlists        map[string]*WBGlist
	DenylistedNames map[string]bool
	DoubtlistedNames  map[string]*TapirName
	RpzOutput        []RpzName
	MqttStats        MqttStats
	TopicData        map[string]TopicData
	ReaperStats      map[string]map[time.Time][]string
	Msg              string
	Error            bool
	ErrorMsg         string
}

type MqttStats struct {
	MsgCounters   map[string]uint32
	MsgTimeStamps map[string]time.Time
}

type Api struct {
	Name       string
	Client     *http.Client
	BaseUrl    string
	ApiKey     string
	Authmethod string
	Verbose    bool
	Debug      bool
}

type ShowAPIresponse struct {
	Status int
	Msg    string
	Data   []string
}

type PingPost struct {
	Msg   string
	Pings int
}

type PingResponse struct {
	Time       time.Time
	BootTime   time.Time
	Daemon     string
	ServerHost string
	Version    string
	Client     string
	Msg        string
	Pings      int
	Pongs      int
}

// MqttPkg is what is sent to the MQTT Engine and returned when an incoming message is parsed.
type MqttPkgOut struct {
	Type      string // text | data, only used on sender side
	Error     bool   // only used for sub.
	ErrorMsg  string // only used for sub.
	Msg       string
	Topic     string // topic on which this message arrived
	Retain    bool
	Data      TapirMsg
	RawData   interface{} // outgoing data, an unparsed struct
	TimeStamp time.Time   // time mqtt packet was sent or received, mgmt by MQTT Engine
}

type MqttPkgIn struct {
	Type     string // text | data, only used on sender side
	Error    bool   // only used for sub.
	ErrorMsg string // only used for sub.
	Msg      string
	Topic    string // topic on which this message arrived
	Retain   bool
	//	Data      TapirMsg
	//	RawData   interface{} // outgoing data, an unparsed struct
	Payload   []byte // incoming data, as received from the network
	Validated bool
	TimeStamp time.Time // time mqtt packet was sent or received, mgmt by MQTT Engine
}

// OBE! MqttData is what is returned from the MQTT Engine for unparsed messages. The payload is left as []byte
// because it can be of arbitrary type, not just TapirMsg.
type MqttData struct {
	Topic     string
	Payload   []byte
	Validated bool
}

// TapirMsg is what is recieved over the MQTT bus.
type TapirMsg struct {
	SrcName  string // must match a defined source
	Creator  string // "spark"	|| "tapir-cli"
	MsgType  string // "observation", "reset", "global-config"...
	ListType string // "{allow|deny|doubt}list"
	Added    []Domain
	Removed  []Domain
	Msg      string
	//	GlobalConfig        GlobalConfig
	//	TapirFunctionStatus TapirFunctionStatus
	TimeStamp time.Time // time encoded in the payload by the sender, not touched by MQTT
	TimeStr   string    // time string encoded in the payload by the sender, not touched by MQTT
}

// Things we need to have in the global config include:
// - dns-tapir bootstrap server details
// - number of RRs to send in a dns.Envelope{}
type GlobalConfig struct {
	TapirConfigVersion string
	Rpz                struct {
		EnvelopeSize int // Number of dns.RRs per zone transfer envelope
	}
	Bootstrap struct {
		Servers  []string
		BaseUrl  string
		ApiToken string
	}
	ObservationTopics []GlobalConfigTopic
	StatusTopics      []GlobalConfigTopic
}

type GlobalConfigTopic struct {
	Topic       string // Topic to subscribe (down) or publish (up) on
	PubKeyName  string // Set when sending a validation key, unset otherwise
	PrivKeyName string // Set when sending a signing key, unset otherwise
}

type Domain struct {
	Name         string
	TimeAdded    time.Time
	TTL          int     // in seconds
	TagMask      TagMask // here is the bitfield
	ExtendedTags []string
	// Action  Action  // another bitfield: (NXDOMAIN, NODATA, DROP, REDIRECT)
}

type MqttEngine struct {
	Running           bool
	Creator           string
	ClientID          string
	Server            string
	QoS               int
	ConnectionManager *autopaho.ConnectionManager
	ClientCert        tls.Certificate
	CaCertPool        *x509.CertPool
	MsgChan           chan paho.PublishReceived
	CmdChan           chan MqttEngineCmd
	PublishChan       chan MqttPkgOut
	SubscribeChan     chan MqttPkgIn
	TopicData         map[string]TopicData // map[topic]TopicData
	PrefixTopics      map[string]bool      // eg. "pubkey/up/" is a prefix topic if we subscribe to pubkey/up/#
	CanPublish        bool                 // can publish to all topics
	CanSubscribe      bool                 // can subscribe to all topics
	Logger            *log.Logger
	Cancel            context.CancelFunc
}

type TopicData struct {
	Topic        string // topic must be in the TopicData, because sometimes we change it, and we need to keep the TopicData entry.
	SigningKey   *ecdsa.PrivateKey
	Sign         bool
	ValidatorKey *ecdsa.PublicKey
	Validate     bool   // should incoming messages be validated by the validator key?
	PubMode      string // "raw" indicates that the data should just be passed through untouched
	SubMode      string // "raw" indicates that the data should just be passed through untouched
	SubscriberCh chan MqttPkgIn
	PubMsgs      uint32
	SubMsgs      uint32
	LatestPub    time.Time
	LatestSub    time.Time
}
type MqttEngineCmd struct {
	Cmd  string
	Resp chan MqttEngineResponse
}

type MqttEngineResponse struct {
	Status   string
	Error    bool
	ErrorMsg string
}

type MqttDetails struct {
	ValidatorKeys map[string]*ecdsa.PublicKey // map[topic]*key
	Bootstrap     []string
	BootstrapUrl  string
	BootstrapKey  string
}

type WBGlist struct {
	Name        string
	Description string
	Type        string // allowlist | denylist | doubtlist
	Immutable   bool   // true = won't be updated by globalconfig topic.
	SrcFormat   string // Format of external source: dawg | rpz | tapir-mqtt-v1 | ...
	Format      string // Format of internal storage: dawg | map | slice | trie | rbtree | ...
	Datasource  string // file | xfr | mqtt | https | api | ...
	Filename    string
	Upstream    string
	Dawgf       dawg.Finder
	MqttDetails *MqttDetails

	// doubtlist sources needs more complex stuff here:
	//	DoubtNames   map[string]DoubtName
	RpzZoneName string
	RpzUpstream string
	RpzSerial   int
	Names       map[string]TapirName // XXX: same data as in ZoneData.RpzData, should only keep one
	ReaperData  map[time.Time]map[string]bool
	// Trie        trie.Trie
}

type TapirName struct {
	//	SrcFormat string          // "tapir-feed-v1" | ...
	Name      string
	TimeAdded time.Time
	TTL       time.Duration
	// Tags    []string // XXX: extremely wasteful, a bitfield would be better,
	TagMask TagMask // bitfield
	NumTags uint8
	//      but don't know how many tags there can be
	Action Action // bitfield NXDOMAIN|NODATA|DROP|...
}

type RpzName struct {
	Name   string
	RR     *dns.RR
	Action Action
}

// func (w *WBGlist) ProtoReflect() protoreflect.Message {
// Assuming you have a generated protobuf message for WBGlist
//	return &tapirpb.WBGlist{
//		Name:        w.Name,
//		Description: w.Description,
//		Type:        w.Type,
//		SrcFormat:   w.SrcFormat,
//		Format:      w.Format,
//		Datasource:  w.Datasource,
//		Filename:    w.Filename,
//		Upstream:    w.Upstream,
//		RpzZoneName: w.RpzZoneName,
//		RpzUpstream: w.RpzUpstream,
//		RpzSerial:   int32(w.RpzSerial),
//		Names:       convertNamesToProto(w.Names),
//		ReaperData:  convertReaperDataToProto(w.ReaperData),
//	}
//}

// func convertNamesToProto(names map[string]TapirName) map[string]*tapirpb.TapirName {
//	protoNames := make(map[string]*tapirpb.TapirName)
//	for k, v := range names {
//		protoNames[k] = &tapirpb.TapirName{
//			Name:      v.Name,
//			TimeAdded: timestamppb.New(v.TimeAdded),
//			TTL:       durationpb.New(v.TTL),
//			TagMask:   uint32(v.TagMask),
//			NumTags:   uint32(v.NumTags),
//			Action:    uint32(v.Action),
//		}
//	}
//	return protoNames
// }

// func convertReaperDataToProto(reaperData map[time.Time]map[string]bool) map[string]*tapirpb.ReaperData {
// 	protoReaperData := make(map[string]*tapirpb.ReaperData)
// 	for k, v := range reaperData {
// 		protoReaperData[k.Format(time.RFC3339)] = &tapirpb.ReaperData{
// 			Entries: v,
// 		}
// 	}
// 	return protoReaperData
// }

// ComponentStatusUpdate is used to send status updates for a single component of a "function" (tapir-pop, tapir-edm, etc)
type ComponentStatusUpdate struct {
	Status    ComponentStatus
	Function  string // tapir-pop | tapir-edm | ...
	Component string // downstream | rpz | mqtt | config | ...
	Msg       string
	TimeStamp time.Time
	Response  chan StatusUpdaterResponse
}
type StatusUpdaterResponse struct {
	FunctionStatus  TapirFunctionStatus
	KnownComponents []string
	Msg             string
	Error           bool
	ErrorMsg        string
}

// TapirFunctionStatus contains the status for all components of this "function" (tapir-pop, tapir-edm, etc)
type TapirFunctionStatus struct {
	Function        string // tapir-pop | tapir-edm | ...
	FunctionID      string
	ComponentStatus map[string]TapirComponentStatus // downstreamnotify | downstreamixfr | rpzupdate | mqttmsg | config | ...
	NumFailures     int
	LastFailure     time.Time
}

// TapirComponentStatus contains the status for a single component of a "function" (tapir-pop, tapir-edm, etc)
type TapirComponentStatus struct {
	Component   string
	Status      ComponentStatus
	ErrorMsg    string
	WarningMsg  string
	Msg         string
	NumFails    int
	NumWarnings int
	LastFail    time.Time
	LastWarn    time.Time
	LastSuccess time.Time
}

// Status alternatives known to StatusUpdater()
type ComponentStatus uint8

const (
	StatusFail ComponentStatus = iota
	StatusWarn
	StatusOK
	StatusReport // Not a component status, but a request for a status report
)

var StringToStatus = map[string]ComponentStatus{
	"ok":     StatusOK,
	"warn":   StatusWarn,
	"fail":   StatusFail,
	"report": StatusReport,
}

var StatusToString = map[ComponentStatus]string{
	StatusOK:     "ok",
	StatusWarn:   "warn",
	StatusFail:   "fail",
	StatusReport: "report",
}

type TapirPubKey struct {
	Pubkey string
}

type PubKeyUpload struct {
	JWSMessage    string
	Signature     string
	ClientCertPEM string
}
