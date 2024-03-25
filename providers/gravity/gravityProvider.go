package gravity

import (
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/net/idna"

	"beryju.io/gravity/api"
	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff2"
	"github.com/StackExchange/dnscontrol/v4/pkg/printer"
	"github.com/StackExchange/dnscontrol/v4/pkg/transform"
	"github.com/StackExchange/dnscontrol/v4/providers"
	"github.com/cloudflare/cloudflare-go"
	"github.com/fatih/color"
)

var _ = api.ContextServerVariables

/*

Gravity API DNS provider:

Info required in `creds.json`:
   - apikey
   - apiuser
   - accountid (optional)

Record level metadata available:
   - cloudflare_proxy ("on", "off", or "full")

Domain level metadata available:
   - cloudflare_proxy_default ("on", "off", or "full")

 Provider level metadata available:
   - ip_conversions
*/

var features = providers.DocumentationNotes{
	// The default for unlisted capabilities is 'Cannot'.
	// See providers/capabilities.go for the entire list of capabilities.
	providers.CanGetZones:      providers.Can(),
	providers.CanUsePTR:        providers.Can(),
	providers.CanUseSRV:        providers.Can(),
	providers.DocCreateDomains: providers.Can(),
}

func init() {
	fns := providers.DspFuncs{
		Initializer:   newGravity,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType("GRAVITY", fns, features)
}

// gravityProvider is the handle for API calls.
type gravityProvider struct {
	domainIndex     map[string]string // Call c.fetchDomainList() to populate before use.
	nameservers     map[string][]string
	ipConversions   []transform.IPConversion
	ignoredLabels   []string
	manageRedirects bool
	manageWorkers   bool
	accountID       string
	gravityClient   *api.APIClient
}

// GetNameservers returns the nameservers for a domain.
func (p *gravityProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	if p.domainIndex == nil {
		if err := p.fetchDomainList(); err != nil {
			return nil, err
		}
	}
	ns, ok := p.nameservers[domain]
	if !ok {
		return nil, fmt.Errorf("nameservers for %s not found in cloudflare account", domain)
	}
	return models.ToNameservers(ns)
}

// ListZones returns a list of the DNS zones.
func (p *gravityProvider) ListZones() ([]string, error) {
	if err := p.fetchDomainList(); err != nil {
		return nil, err
	}
	zones := make([]string, 0, len(p.domainIndex))
	for d := range p.domainIndex {
		zones = append(zones, d)
	}
	return zones, nil
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (p *gravityProvider) GetZoneRecords(domain string, meta map[string]string) (models.Records, error) {

	records, err := p.getRecordsForDomain(domain)
	if err != nil {
		return nil, err
	}

	for _, rec := range records {
		if rec.TTL == 0 {
			rec.TTL = 1
		}
		// Store the proxy status ("orange cloud") for use by get-zones:
		m := getProxyMetadata(rec)
		if p, ok := m["proxy"]; ok {
			if rec.Metadata == nil {
				rec.Metadata = map[string]string{}
			}
			rec.Metadata["cloudflare_proxy"] = p
		}
	}

	// Normalize
	models.PostProcessRecords(records)

	return records, nil
}

func (p *gravityProvider) getDomainID(name string) (string, error) {
	if p.domainIndex == nil {
		if err := p.fetchDomainList(); err != nil {
			return "", err
		}
	}
	id, ok := p.domainIndex[name]
	if !ok {
		return "", fmt.Errorf("'%s' not a zone in Gravity", name)
	}
	return id, nil
}

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records.
func (p *gravityProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, records models.Records) ([]*models.Correction, error) {

	checkNSModifications(dc)

	// domainID, err := p.getDomainID(dc.Name)
	// if err != nil {
	// 	return nil, err
	// }

	checkNSModifications(dc)

	var corrections []*models.Correction

	// Gravity is a "ByRecord" API.
	instructions, err := diff2.ByRecord(records, dc, genComparable)
	if err != nil {
		return nil, err
	}

	for _, inst := range instructions {

		var corrs []*models.Correction

		// domainID := domainID
		msg := inst.Msgs[0]

		switch inst.Type {
		case diff2.CREATE:
			createRec := inst.New[0]
			corrs = p.mkCreateCorrection(createRec, dc.Name, msg)
		case diff2.CHANGE:
			newrec := inst.New[0]
			oldrec := inst.Old[0]
			corrs = p.mkChangeCorrection(oldrec, newrec, dc.Name, msg)
		case diff2.DELETE:
			deleteRec := inst.Old[0]
			deleteRecType := deleteRec.Type
			deleteRecOrig := deleteRec.Original
			corrs = p.mkDeleteCorrection(deleteRecType, deleteRecOrig, dc.Name, msg)
		}

		corrections = append(corrections, corrs...)

	}

	return corrections, nil
}

func genComparable(rec *models.RecordConfig) string {
	if rec.Type == "A" || rec.Type == "AAAA" || rec.Type == "CNAME" {
		proxy := rec.Metadata[metaProxy]
		if proxy != "" {
			if proxy == "on" || proxy == "full" {
				proxy = "true"
			}
			if proxy == "off" {
				proxy = "false"
			}
			return "proxy=" + proxy
		}
	}
	return ""
}

func (p *gravityProvider) mkCreateCorrection(newrec *models.RecordConfig, domainName, msg string) []*models.Correction {

	return p.createRecDiff2(newrec, domainName, msg)

}

func (p *gravityProvider) mkChangeCorrection(oldrec, newrec *models.RecordConfig, hostname string, msg string) []*models.Correction {

	idTxt := oldrec.Original.(cloudflare.DNSRecord).ID

	msg = msg + color.YellowString(" id=%v", idTxt)

	return []*models.Correction{{
		Msg: msg,
		F:   func() error { return p.modifyRecord(hostname, newrec) },
	}}

}

func (p *gravityProvider) mkDeleteCorrection(recType string, origRec any, domainID string, msg string) []*models.Correction {

	idTxt := origRec.(cloudflare.DNSRecord).ID

	msg = msg + color.RedString(" id=%v", idTxt)

	correction := &models.Correction{
		Msg: msg,
		F: func() error {
			return p.deleteDNSRecord(domainID)
		},
	}
	return []*models.Correction{correction}
}

func checkNSModifications(dc *models.DomainConfig) {
	newList := make([]*models.RecordConfig, 0, len(dc.Records))

	punyRoot, err := idna.ToASCII(dc.Name)
	if err != nil {
		punyRoot = dc.Name
	}

	for _, rec := range dc.Records {
		if rec.Type == "NS" && rec.GetLabelFQDN() == punyRoot {
			if strings.HasSuffix(rec.GetTargetField(), ".ns.cloudflare.com.") {
				continue
			}
		}
		newList = append(newList, rec)
	}
	dc.Records = newList
}

const (
	metaProxy         = "cloudflare_proxy"
	metaProxyDefault  = metaProxy + "_default"
	metaOriginalIP    = "original_ip"    // TODO(tlim): Unclear what this means.
	metaIPConversions = "ip_conversions" // TODO(tlim): Rename to obscure_rules.
)

func newGravity(m map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	p := &gravityProvider{}
	// check api keys from creds json file
	if m["apitoken"] == "" && (m["apikey"] == "" || m["apiuser"] == "") {
		return nil, fmt.Errorf("if cloudflare apitoken is not set, apikey and apiuser must be provided")
	}
	if m["apitoken"] != "" && (m["apikey"] != "" || m["apiuser"] != "") {
		return nil, fmt.Errorf("if cloudflare apitoken is set, apikey and apiuser should not be provided")
	}

	p.gravityClient = api.NewAPIClient(&api.Configuration{})

	// Check account data if set
	if m["accountid"] != "" {
		p.accountID = m["accountid"]
	}

	// debug, err := strconv.ParseBool(os.Getenv("CLOUDFLAREAPI_DEBUG"))
	// if err == nil {
	// 	p.cfClient.Debug = debug
	// }

	if len(metadata) > 0 {
		parsedMeta := &struct {
			IPConversions string   `json:"ip_conversions"`
			IgnoredLabels []string `json:"ignored_labels"`
		}{}
		err := json.Unmarshal([]byte(metadata), parsedMeta)
		if err != nil {
			return nil, err
		}
		// ignored_labels:
		p.ignoredLabels = append(p.ignoredLabels, parsedMeta.IgnoredLabels...)
		if len(p.ignoredLabels) > 0 {
			printer.Warnf("Cloudflare 'ignored_labels' configuration is deprecated and might be removed. Please use the IGNORE domain directive to achieve the same effect.\n")
		}
		// parse provider level metadata
		if len(parsedMeta.IPConversions) > 0 {
			p.ipConversions, err = transform.DecodeTransformTable(parsedMeta.IPConversions)
			if err != nil {
				return nil, err
			}
		}
	}
	return p, nil
}

// Used on the "existing" records.
type cfRecData struct {
	Name     string   `json:"name"`
	Target   cfTarget `json:"target"`
	Service  string   `json:"service"`  // SRV
	Proto    string   `json:"proto"`    // SRV
	Priority uint16   `json:"priority"` // SRV
	Weight   uint16   `json:"weight"`   // SRV
	Port     uint16   `json:"port"`     // SRV
}

// cfTarget is a SRV target. A null target is represented by an empty string, but
// a dot is so acceptable.
type cfTarget string

// UnmarshalJSON decodes a SRV target from the Cloudflare API. A null target is
// represented by a false boolean or a dot. Domain names are FQDNs without a
// trailing period (as of 2019-11-05).
func (c *cfTarget) UnmarshalJSON(data []byte) error {
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	switch v := obj.(type) {
	case string:
		*c = cfTarget(v)
	case bool:
		if v {
			panic("unknown value for cfTarget bool: true")
		}
		*c = "" // the "." is already added by nativeToRecord
	}
	return nil
}

// MarshalJSON encodes cfTarget for the Cloudflare API. Null targets are
// represented by a single period.
func (c cfTarget) MarshalJSON() ([]byte, error) {
	var obj string
	switch c {
	case "", ".":
		obj = "."
	default:
		obj = string(c)
	}
	return json.Marshal(obj)
}

// DNSControlString returns cfTarget normalized to be a FQDN. Null targets are
// represented by a single period.
func (c cfTarget) FQDN() string {
	return strings.TrimRight(string(c), ".") + "."
}

// uint16Zero converts value to uint16 or returns 0.
func uint16Zero(value interface{}) uint16 {
	switch v := value.(type) {
	case float64:
		return uint16(v)
	case uint16:
		return v
	case nil:
	}
	return 0
}

// int32Zero converts value to int16 or returns 0.
func int32Zero(value interface{}) *int32 {
	var retValue int32

	switch v := value.(type) {
	case float64:
		retValue = int32(v)
	case uint16:
		retValue = int32(v)
	case uint32:
		retValue = int32(v)
	case nil:
	}
	return &retValue
}

// intZero converts value to int or returns 0.
func intZero(value interface{}) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case nil:
	}
	return 0
}

// stringDefault returns the value as a string or returns the default value if nil.
func stringDefault(value interface{}, def string) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
	}
	return def
}

func (p *gravityProvider) nativeToRecord(domain string, native api.DnsAPIRecord) (*models.RecordConfig, error) {

	// normalize cname,mx,ns records with dots to be consistent with our config format.
	if native.Type == "CNAME" || native.Type == "MX" || native.Type == "NS" || native.Type == "PTR" {
		if native.Data != "." {
			native.Data = native.Data + "."
		}
	}

	rc := &models.RecordConfig{
		TTL:      uint32(0),
		Original: native,
		Metadata: map[string]string{},
	}
	rc.SetLabelFromFQDN(native.Hostname, domain)

	switch rType := native.Type; rType { // #rtype_variations
	case "MX":
		if err := rc.SetTargetMX(uint16Zero(native.MxPreference), native.Data); err != nil {
			return nil, fmt.Errorf("unparsable MX record received from Gravity: %w", err)
		}
	case "SRV":
		// data := native.Data.(map[string]interface{})

		// target := stringDefault(data["target"], "MISSING.TARGET")
		// if target != "." {
		// 	target += "."
		// }
		if err := rc.SetTargetSRV(uint16Zero(native.SrvPriority), uint16Zero(native.SrvWeight), uint16Zero(native.SrvPort),
			native.Fqdn); err != nil {
			return nil, fmt.Errorf("unparsable SRV record received from Gravity: %w", err)
		}
	case "TXT":
		err := rc.SetTargetTXT(native.Data)
		return rc, err
	default:
		if err := rc.PopulateFromString(rType, native.Data, domain); err != nil {
			return nil, fmt.Errorf("unparsable record received from cloudflare: %w", err)
		}
	}

	return rc, nil
}

func getProxyMetadata(r *models.RecordConfig) map[string]string {
	if r.Type != "A" && r.Type != "AAAA" && r.Type != "CNAME" {
		return nil
	}
	var proxied bool
	if r.Original != nil {
		proxied = *r.Original.(cloudflare.DNSRecord).Proxied
	} else {
		proxied = r.Metadata[metaProxy] != "off"
	}
	return map[string]string{
		"proxy": fmt.Sprint(proxied),
	}
}

// EnsureZoneExists creates a zone if it does not exist
func (p *gravityProvider) EnsureZoneExists(domain string) error {
	if p.domainIndex == nil {
		if err := p.fetchDomainList(); err != nil {
			return err
		}
	}
	if _, ok := p.domainIndex[domain]; ok {
		return nil
	}

	err := p.createZone(domain, false, 300)
	printer.Printf("Added zone for %s\n", domain)
	p.domainIndex = nil // clear the index to let the following functions get a fresh list with nameservers etc..
	return err
}
