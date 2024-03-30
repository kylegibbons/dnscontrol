package gravity

import (
	"context"
	"fmt"
	"strings"

	"beryju.io/gravity/api"

	"github.com/StackExchange/dnscontrol/v4/models"
)

// get list of domains for account. Cache so the ids can be looked up from domain name
// This provider does not support nameservers, an empty string is always returned
func (p *gravityProvider) fetchDomainList() error {
	p.zones = map[string]api.DnsAPIZone{}
	p.nameservers = map[string][]string{}
	zones, _, err := p.gravityClient.RolesDnsApi.DnsGetZones(context.Background()).Execute()

	if err != nil {
		return fmt.Errorf("failed fetching domain list from gravity(%q): %s", "id", err)
	}

	for _, zone := range zones.Zones {

		// if encoded, err := idna.ToASCII(zone.Name); err == nil && encoded != zone.Name {
		// 	p.zones[encoded] = zone
		// 	p.nameservers[encoded] = append(p.nameservers[encoded], "gibb.network")
		// }
		zone.Name = strings.TrimSuffix(zone.Name, ".")

		p.zones[zone.Name] = zone
		p.nameservers[zone.Name] = append(p.nameservers[zone.Name], "gibb.network")
	}

	// fmt.Printf("FETCH LIST: %+v\n", zones)
	// fmt.Printf("SAVED LIST: %+v\n", p.zones)

	return nil
}

// get all records for a domain
func (p *gravityProvider) getRecordsForDomain(domain string) ([]*models.RecordConfig, error) {
	records := []*models.RecordConfig{}
	rrs, _, err := p.gravityClient.RolesDnsApi.DnsGetRecords(context.Background()).Zone(domain + ".").Execute()

	if err != nil {
		return nil, fmt.Errorf("failed fetching record list from cloudflare(%q): %w", "id", err)
	}

	for _, rec := range rrs.Records {
		rt, err := p.nativeToRecord(domain, rec)
		if err != nil {
			return nil, err
		}
		records = append(records, rt)
	}
	return records, nil
}

func (p *gravityProvider) deleteDNSRecord(zone string, hostname string) error {
	_, err := p.gravityClient.RolesDnsApi.DnsDeleteRecords(context.Background()).
		Zone(zone).
		Hostname(hostname).Execute()

	return err
}

func (p *gravityProvider) createZone(domainName string, authoritative bool, defaultTTL int32) error {

	// Setup default handler configs
	handlerConfigs := make([]map[string]string, 2)

	handlerConfigs[0] = make(map[string]string)
	handlerConfigs[0]["type"] = "memory"

	handlerConfigs[1] = make(map[string]string)
	handlerConfigs[1]["type"] = "etcd"

	_, err := p.gravityClient.RolesDnsApi.DnsPutZones(context.Background()).
		Zone(domainName).
		DnsAPIZonesPutInput(api.DnsAPIZonesPutInput{
			Authoritative:  authoritative,
			DefaultTTL:     defaultTTL,
			HandlerConfigs: handlerConfigs,
		}).
		Execute()

	return err
}

func (p *gravityProvider) createRecDiff2(rec *models.RecordConfig, zone string, msg string) []*models.Correction {

	content := rec.GetTargetField()

	prio := ""
	if rec.Type == "MX" {
		prio = fmt.Sprintf(" %d ", rec.MxPreference)
	}
	if rec.Type == "TXT" {
		content = rec.GetTargetTXTJoined()
	}
	if msg == "" {
		msg = fmt.Sprintf("CREATE record: %s %s %d%s %s", rec.GetLabel(), rec.Type, rec.TTL, prio, content)
	}

	arr := []*models.Correction{{
		Msg: msg,
		F: func() error {
			gr := api.DnsAPIRecordsPutInput{
				Type: rec.Type,
				Data: content,
			}
			if rec.Type == "SRV" {
				gr.SrvPort = int32Zero(rec.SrvPort)
				gr.SrvPriority = int32Zero(rec.SrvPriority)
				gr.SrvWeight = int32Zero(rec.SrvWeight)
			}
			if rec.Type == "MX" {
				gr.MxPreference = int32Zero(rec.MxPreference)
			}

			_, err := p.gravityClient.RolesDnsApi.DnsPutRecords(context.Background()).
				DnsAPIRecordsPutInput(gr).
				Zone(zone + ".").
				Hostname(rec.Name).
				Execute()

			if err != nil {
				return err
			}

			return nil
		},
	}}
	return arr
}

func (p *gravityProvider) modifyRecord(hostname string, rec *models.RecordConfig) error {
	if hostname == "" {
		return fmt.Errorf("cannot modify record if hostname is empty")
	}

	mxPref := int32(rec.MxPreference)

	gr := api.DnsAPIRecordsPutInput{
		Type:         rec.Type,
		Data:         rec.GetTargetField(),
		MxPreference: int32Zero(mxPref),
	}
	if rec.Type == "TXT" {
		gr.Data = rec.GetTargetTXTJoined()
	}
	if rec.Type == "SRV" {
		gr.SrvPort = int32Zero(rec.SrvPort)
		gr.SrvPriority = int32Zero(rec.SrvPriority)
		gr.SrvWeight = int32Zero(rec.SrvWeight)
	}

	_, err := p.gravityClient.RolesDnsApi.DnsPutRecords(context.Background()).DnsAPIRecordsPutInput(gr).Execute()

	return err
}
