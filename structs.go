/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
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
	ListName  string // used in the export-greylist command
	Policy    string // RPZ policy
	Action    string // RPZ action (OBE)
	RpzSource string // corresponds with the sourceid in tem.yaml
}

type CommandResponse struct {
	Time      time.Time
	Status    string
	Zone      string
	Serial    uint32
	Data      []byte
	Msg       string
	TemStatus TemStatus
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
	Command string
	Zone    string
	Qname   string
	Qtype   uint16
}

type DebugResponse struct {
	Time   time.Time
	Status string
	Zone   string
	//	ZoneData   ZoneData
	OwnerIndex       map[string]int
	RRset            RRset
	Lists            map[string]map[string]*WBGlist
	Whitelists       map[string]*WBGlist
	Blacklists       map[string]*WBGlist
	Greylists        map[string]*WBGlist
	BlacklistedNames map[string]bool
	GreylistedNames  map[string]*TapirName
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

type MqttPkg struct {
	Type      string // text | data, only used on sender side
	Error     bool   // only used for sub.
	ErrorMsg  string // only used for sub.
	Msg       string
	Topic     string // topic on which this message arrived
	Retain    bool
	Data      TapirMsg
	TemStatus TemStatus
	TimeStamp time.Time // time mqtt packet was sent or received, mgmt by MQTT Engine
}

// TapirMsg is what is recieved over the MQTT bus.
type TapirMsg struct {
	SrcName      string // must match a defined source
	Creator      string // "spark"	|| "tapir-cli"
	MsgType      string // "observation", "reset", "global-config"...
	ListType     string // "{white|black|grey}list"
	Added        []Domain
	Removed      []Domain
	Msg          string
	GlobalConfig GlobalConfig
	TimeStamp    time.Time // time encoded in the payload by the sender, not touched by MQTT
	TimeStr      string    // time string encoded in the payload by the sender, not touched by MQTTs
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
		Servers []string
		BaseUrl string
		ApiKey  string
	}
}

type Domain struct {
	Name      string
	TimeAdded time.Time
	//	TTL       time.Duration
	TTL     int     // in seconds
	TagMask TagMask // here is the bitfield
	Action  Action  // another bitfield: (NXDOMAIN, NODATA, DROP, REDIRECT)
}

type MqttEngine struct {
	Topic    string
	ClientID string
	Server   string
	QoS      int
	//	PrivKey           *ecdsa.PrivateKey
	//	PubKey            any
	ConnectionManager *autopaho.ConnectionManager
	ClientCert        tls.Certificate
	CaCertPool        *x509.CertPool
	MsgChan           chan paho.PublishReceived
	CmdChan           chan MqttEngineCmd
	PublishChan       chan MqttPkg
	SubscribeChan     chan MqttPkg
	// SigningKeys       map[string]*ecdsa.PrivateKey // map[topic]*key
	// ValidatorKeys     map[string]*ecdsa.PublicKey  // map[topic]*key
	TopicData map[string]TopicData // map[topic]TemStatus
	// MsgCounters       map[string]uint32            // map[topic]counter
	//MsgTimeStamps     map[string]time.Time         // map[topic]timestamp
	CanPublish   bool // can publish to all topics
	CanSubscribe bool // can subscribe to all topics
	Logger       *log.Logger
	Cancel       context.CancelFunc
}

type TopicData struct {
	SigningKey   *ecdsa.PrivateKey
	ValidatorKey *ecdsa.PublicKey
	SubscriberCh chan MqttPkg
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
}

type WBGlist struct {
	Name        string
	Description string
	Type        string // whitelist | blacklist | greylist
	//	Mutable     bool   // true = is possible to update. Only local text file sources are mutable
	SrcFormat   string // Format of external source: dawg | rpz | tapir-mqtt-v1 | ...
	Format      string // Format of internal storage: dawg | map | slice | trie | rbtree | ...
	Datasource  string // file | xfr | mqtt | https | api | ...
	Filename    string
	Upstream    string
	Dawgf       dawg.Finder
	MqttDetails *MqttDetails

	// greylist sources needs more complex stuff here:
	//	GreyNames   map[string]GreyName
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

type TemStatusUpdate struct {
	Status    string
	Component string // downstream | rpz | mqtt | config | ...
	Msg       string
	Response  chan TemStatus
}

type TemStatus struct {
	ComponentStatus map[string]string    // downstreamnotify | downstreamixfr | rpzupdate | mqttmsg | config | ...
	TimeStamps      map[string]time.Time // downstreamnotify | downstreamixfr | rpzupdate | mqttmsg | config | ...
	Counters        map[string]int       // downstreamnotify | downstreamixfr | rpzupdate | mqttmsg | config | ...
	ErrorMsgs       map[string]string    // downstreamnotify | downstreamixfr | rpzupdate | mqttmsg | config | ...
	NumFailures     int
	LastFailure     time.Time
}
