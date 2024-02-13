/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tapir

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"time"

	"github.com/Pashugan/trie"
	"github.com/eclipse/paho.golang/paho"
	"github.com/miekg/dns"
	"github.com/smhanov/dawg"
)

type ZoneType uint8

const (
	XfrZone ZoneType = iota
	MapZone
	SliceZone
	RpzZone
)

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
	RRKeepFunc     func(uint16) bool
	RRParseFunc    func(*dns.RR, *ZoneData) bool
	Verbose        bool
	Debug          bool
	RpzData        map[string]string // map[ownername]action. owner w/o rpz zone name
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
	Policy    string // RPZ policy
	Action    string // RPZ action (OBE)
	RpzSource string // corresponds with the sourceid in tem.yaml
}

type CommandResponse struct {
	Time     time.Time
	Status   string
	Zone     string
	Serial   uint32
	Msg      string
	Error    bool
	ErrorMsg string
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
	Msg              string
	Error            bool
	ErrorMsg         string
}

type Api struct {
	Name       string
	Client     *http.Client
	BaseUrl    string
	apiKey     string
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
	Data      TapirMsg
	TimeStamp time.Time // time mqtt packet was sent or received, mgmt by MQTT Engine
}

type TapirMsg struct {
	SrcName   string // must match a defined source
	MsgType   string // "intelupdate", "reset", ...
	ListType  string // "{white|black|grey}list"
	Added     []Domain
	Removed   []Domain
	Msg       string
	TimeStamp time.Time // time encoded in the payload by the sender, not touched by MQTT
}

type Domain struct {
	Name    string
	Tags    []string // this should become a bit field in the future
	Tagmask TagMask  // here is the bitfield
	Action  Action   // another bitfield: (NXDOMAIN, NODATA, DROP, REDIRECT)
}

type MqttEngine struct {
	Topic         string
	ClientID      string
	Server        string
	QoS           int
	PrivKey       *ecdsa.PrivateKey
	PubKey        any
	Client        *paho.Client
	ClientCert    tls.Certificate
	CaCertPool    *x509.CertPool
	MsgChan       chan *paho.Publish
	CmdChan       chan MqttEngineCmd
	PublishChan   chan MqttPkg
	SubscribeChan chan MqttPkg
	CanPublish    bool
	CanSubscribe  bool
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

type WBGlist struct {
	Name        string
	Description string
	Type        string // whitelist | blacklist | greylist
	//	Mutable     bool   // true = is possible to update. Only local text file sources are mutable
	SrcFormat  string // Format of external source: dawg | rpz | tapir-mqtt-v1 | ...
	Format     string // Format of internal storage: dawg | map | slice | trie | rbtree | ...
	Datasource string // file | xfr | mqtt | https | api | ...
	Filename   string
	Dawgf      dawg.Finder

	// greylist sources needs more complex stuff here:
	//	GreyNames   map[string]GreyName
	RpzZoneName string
	RpzUpstream string
	RpzSerial   int
	Names       map[string]TapirName // XXX: same data as in ZoneData.RpzData, should only keep one
	Trie        trie.Trie
}

type TapirName struct {
	//	SrcFormat string          // "tapir-feed-v1" | ...
	Name    string
	Tags    []string // XXX: extremely wasteful, a bitfield would be better,
	Tagmask TagMask  // bitfield
	NumTags uint8
	//      but don't know how many tags there can be
	Action Action // bitfield NXDOMAIN|NODATA|DROP|...
}

type RpzName struct {
	Name   string
	RR     *dns.RR
	Action Action
}
