package gravity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"beryju.io/gravity/api"
	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff2"
	"github.com/StackExchange/dnscontrol/v4/pkg/printer"
	"github.com/StackExchange/dnscontrol/v4/providers"
	"github.com/fatih/color"
	httptransport "github.com/go-openapi/runtime/client"
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
	zones         map[string]api.DnsAPIZone // Call c.fetchDomainList() to populate before use.
	nameservers   map[string][]string
	gravityClient *api.APIClient
}

// GetNameservers returns the nameservers for a domain.
func (p *gravityProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	fmt.Println("In Get Nameservers")
	if p.zones == nil {
		if err := p.fetchDomainList(); err != nil {
			return nil, err
		}
	}
	ns, ok := p.nameservers[domain]
	if !ok {
		return nil, fmt.Errorf("nameservers for %s not found in Gravity", domain)
	}
	return models.ToNameservers(ns)
}

// ListZones returns a list of the DNS zones.
func (p *gravityProvider) ListZones() ([]string, error) {

	fmt.Println("in List Zones")

	if err := p.fetchDomainList(); err != nil {
		return nil, err
	}
	zones := make([]string, 0, len(p.zones))
	for d := range p.zones {
		zones = append(zones, strings.TrimSuffix(d, "."))
	}
	return zones, nil
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (p *gravityProvider) GetZoneRecords(domain string, meta map[string]string) (models.Records, error) {

	fmt.Println("Getting Zone Records")

	records, err := p.getRecordsForDomain(domain)
	if err != nil {
		return nil, err
	}

	for _, rec := range records {
		if rec.TTL == 0 {
			rec.TTL = 1
		}
	}

	// Normalize
	models.PostProcessRecords(records)

	return records, nil
}

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records.
func (p *gravityProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, records models.Records) ([]*models.Correction, error) {
	fmt.Println("looking for Gravity corrections")
	// checkNSModifications(dc)

	// domainID, err := p.getDomainID(dc.Name)
	// if err != nil {
	// 	return nil, err
	// }

	// checkNSModifications(dc)

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
			deleteRecOrig := deleteRec.Original
			corrs = p.mkDeleteCorrection(deleteRecOrig, dc.Name, msg)
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

	idTxt := oldrec.Original.(api.DnsAPIRecord).Hostname

	msg = msg + color.YellowString(" hostname=%v", idTxt)

	return []*models.Correction{{
		Msg: msg,
		F:   func() error { return p.modifyRecord(hostname, newrec) },
	}}

}

func (p *gravityProvider) mkDeleteCorrection(origRec any, domainID string, msg string) []*models.Correction {

	idTxt := origRec.(api.DnsAPIRecord).Hostname
	zone := origRec.(api.DnsAPIRecord).Fqdn

	msg = msg + color.RedString(" hostname=%v", idTxt)

	correction := &models.Correction{
		Msg: msg,
		F: func() error {
			return p.deleteDNSRecord(zone, domainID)
		},
	}
	return []*models.Correction{correction}
}

// func checkNSModifications(dc *models.DomainConfig) {
// 	newList := make([]*models.RecordConfig, 0, len(dc.Records))

// 	punyRoot, err := idna.ToASCII(dc.Name)
// 	if err != nil {
// 		punyRoot = dc.Name
// 	}

// 	for _, rec := range dc.Records {
// 		if rec.Type == "NS" && rec.GetLabelFQDN() == punyRoot {
// 			if strings.HasSuffix(rec.GetTargetField(), ".ns.cloudflare.com.") {
// 				continue
// 			}
// 		}
// 		newList = append(newList, rec)
// 	}
// 	dc.Records = newList
// }

const (
	metaProxy         = "cloudflare_proxy"
	metaProxyDefault  = metaProxy + "_default"
	metaOriginalIP    = "original_ip"    // TODO(tlim): Unclear what this means.
	metaIPConversions = "ip_conversions" // TODO(tlim): Rename to obscure_rules.
)

func newGravity(m map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	p := &gravityProvider{}

	if m["apitoken"] == "" {
		return nil, fmt.Errorf("apitoken is required")
	}

	if m["url"] == "" {
		return nil, fmt.Errorf("url is required")
	}

	insecure := false

	if strings.ToLower(m["InsecureSkipVerify"]) == "true" {
		insecure = true
	}

	debug := false

	if strings.ToLower(m["debug"]) == "true" {
		debug = true
	}

	gURL, err := url.Parse(m["url"])
	if err != nil {
		return nil, err
	}

	config := api.NewConfiguration()
	config.Debug = debug
	config.UserAgent = fmt.Sprintf("dnscontrol-gravity")
	config.Host = gURL.Host
	config.Scheme = gURL.Scheme

	tlsTransport, err := httptransport.TLSTransport(httptransport.TLSClientOptions{
		InsecureSkipVerify: insecure,
	})

	if err != nil {
		return p, err
	}

	config.HTTPClient = &http.Client{
		Transport: tlsTransport,
	}

	config.AddDefaultHeader("Authorization", fmt.Sprintf("Bearer %s", m["apitoken"]))

	p.gravityClient = api.NewAPIClient(config)

	// Check account data if set
	// if m["accountid"] != "" {
	// 	p.accountID = m["accountid"]
	// }

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
		// p.ignoredLabels = append(p.ignoredLabels, parsedMeta.IgnoredLabels...)
		// if len(p.ignoredLabels) > 0 {
		// 	printer.Warnf("Cloudflare 'ignored_labels' configuration is deprecated and might be removed. Please use the IGNORE domain directive to achieve the same effect.\n")
		// }
		// // parse provider level metadata
		// if len(parsedMeta.IPConversions) > 0 {
		// 	p.ipConversions, err = transform.DecodeTransformTable(parsedMeta.IPConversions)
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// }
	}
	return p, nil
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

func (p *gravityProvider) nativeToRecord(domain string, native api.DnsAPIRecord) (*models.RecordConfig, error) {

	domain = strings.TrimSuffix(domain, ".")

	// normalize cname,mx,ns records with dots to be consistent with our config format.
	// if native.Type == "CNAME" || native.Type == "MX" || native.Type == "NS" || native.Type == "PTR" {
	// 	if native.Data != "." {
	// native.Data = native.Data
	// 	}
	// }

	native.Hostname = strings.TrimSuffix(native.Hostname, ".")

	rc := &models.RecordConfig{
		TTL:      uint32(0),
		Original: native,
		Metadata: map[string]string{},
	}
	rc.SetTarget(native.Data)
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

// EnsureZoneExists creates a zone if it does not exist
func (p *gravityProvider) EnsureZoneExists(domain string) error {

	if p.zones == nil {
		if err := p.fetchDomainList(); err != nil {
			return err
		}
	}

	d := domain

	fmt.Printf("Comparing domain: %s\n", d)

	if _, ok := p.zones[d]; ok {
		return nil
	}

	err := p.createZone(domain, false, 300)
	printer.Printf("Added zone for %s\n", domain)
	p.zones = nil // clear the index to let the following functions get a fresh list with nameservers etc..

	return err
}
