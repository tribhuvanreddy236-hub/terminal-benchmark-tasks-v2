package replay

import (
	"encoding/json"
	"os"
	"sort"

	"trustaudit/internal/policy"
)

type Event struct {
	Seq                    int      `json:"seq"`
	EventID                string   `json:"event_id"`
	ServiceID              string   `json:"service_id"`
	Kind                   string   `json:"kind"`
	Tier                   string   `json:"tier"`
	FromService            string   `json:"from_service"`
	ToService              string   `json:"to_service"`
	Capability             string   `json:"capability"`
	CallerID               string   `json:"caller_id"`
	CalleeID               string   `json:"callee_id"`
	Action                 string   `json:"action"`
	HasToken               bool     `json:"has_token"`
	PropagatedCapabilities []string `json:"propagated_capabilities"`
	OriginalCaller         string   `json:"original_caller"`
}

type Scenario struct {
	ScenarioID               string                 `json:"scenario_id"`
	RequireTokenOnInternal   *bool                  `json:"require_token_on_internal"`
	BlockPartnerToPrivileged *bool                  `json:"block_partner_to_privileged"`
	PolicyOverrides          map[string]interface{} `json:"policy_overrides"`
	Events                   []Event                `json:"events"`
}

type EdgeOut struct {
	FromService string `json:"from_service"`
	ToService   string `json:"to_service"`
}

type ServiceOut struct {
	ServiceID         string   `json:"service_id"`
	Tier              string   `json:"tier"`
	Capabilities      []string `json:"capabilities"`
	TrustBoundaryRisk string   `json:"trust_boundary_risk"`
}

type CaptureOut struct {
	FormatVersion   int `json:"format_version"`
	RecordsTotal    int `json:"records_total"`
	RecordsValid    int `json:"records_valid"`
	RecordsRejected int `json:"records_rejected"`
	DupSeqRejects   int `json:"dup_seq_rejects"`
	TruncatedTail   int `json:"truncated_tail"`
	PayloadBytes    int `json:"payload_bytes"`
}

type Finding struct {
	FindingID string `json:"finding_id"`
	EntityID  string `json:"entity_id"`
	Kind      string `json:"kind"`
	EventSeq  int    `json:"event_seq"`
	Action    string `json:"action"`
	Detail    string `json:"detail"`
}

type ScenarioOut struct {
	ScenarioID             string       `json:"scenario_id"`
	Status                 string       `json:"status"`
	DuplicateEventsSkipped int          `json:"duplicate_events_skipped"`
	Capture                CaptureOut   `json:"capture"`
	PeerTrustEdges         []EdgeOut    `json:"peer_trust_edges"`
	Services               []ServiceOut `json:"services"`
	Findings               []Finding    `json:"findings"`
}

type Report struct {
	Scenarios []ScenarioOut `json:"scenarios"`
}

type serviceState struct {
	tier   string
	caps   map[string]struct{}
}

func LoadScenario(path string) (Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Scenario{}, err
	}
	var sc Scenario
	if err := json.Unmarshal(data, &sc); err != nil {
		return Scenario{}, err
	}
	return sc, nil
}

func findingID(scenarioID, entityID string, seq int) string {
	return scenarioID + "::" + entityID + "::" + formatSeq(seq)
}

func formatSeq(seq int) string {
	if seq < 0 {
		seq = 0
	}
	s := []byte("0000")
	n := seq
	for i := 3; i >= 0; i-- {
		s[i] = byte('0' + n%10)
		n /= 10
	}
	return string(s)
}

func strSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func trustBoundaryRisk(tier string) string {
	switch tier {
	case "partner":
		return "elevated"
	case "privileged":
		return "critical"
	default:
		return "none"
	}
}

func callerHasAny(caps map[string]struct{}, propagated []string) bool {
	for _, p := range propagated {
		if _, ok := caps[p]; ok {
			return true
		}
	}
	return len(propagated) == 0
}

func appendFinding(findings *[]Finding, scenarioID, entityID, kind, action, detail string, seq int) {
	*findings = append(*findings, Finding{
		FindingID: findingID(scenarioID, entityID, seq),
		EntityID:  entityID,
		Kind:      kind,
		EventSeq:  seq,
		Action:    action,
		Detail:    detail,
	})
}

func Analyze(sc Scenario, cap CaptureOut) ScenarioOut {
	_ = cap
	requireToken := true
	if sc.RequireTokenOnInternal != nil {
		requireToken = *sc.RequireTokenOnInternal
	}
	blockPartner := true
	if sc.BlockPartnerToPrivileged != nil {
		blockPartner = *sc.BlockPartnerToPrivileged
	}
	requireToken, blockPartner = policy.ResolveBools(
		requireToken,
		blockPartner,
		sc.PolicyOverrides,
	)
	_ = requireToken
	_ = blockPartner

	services := make(map[string]*serviceState)
	edges := make(map[string]struct{})
	findings := make([]Finding, 0)
	dupSkipped := 0
	seenEvent := make(map[string]struct{})
	maxSeq := 0

	events := append([]Event(nil), sc.Events...)
	sort.Slice(events, func(i, j int) bool {
		return events[i].Seq < events[j].Seq
	})

	for _, ev := range events {
		seq := ev.Seq
		if seq > maxSeq {
			maxSeq = seq
		}
		kind := ev.Kind
		_ = seenEvent

		switch kind {
		case "REGISTER_SERVICE":
			sid := ev.ServiceID
			if _, exists := services[sid]; exists {
				appendFinding(&findings, sc.ScenarioID, sid, "DUPLICATE_SERVICE", "", "", seq)
				continue
			}
			services[sid] = &serviceState{tier: ev.Tier, caps: make(map[string]struct{})}
		case "ALLOW_TRUST":
			from := ev.FromService
			to := ev.ToService
			if _, ok := services[from]; !ok {
				appendFinding(&findings, sc.ScenarioID, from, "UNKNOWN_CALLER", "", kind, seq)
				continue
			}
			if _, ok := services[to]; !ok {
				appendFinding(&findings, sc.ScenarioID, to, "UNKNOWN_CALLEE", "", kind, seq)
				continue
			}
			key := from + "->" + to
			edges[key] = struct{}{}
		case "BIND_CAPABILITY":
			sid := ev.ServiceID
			if _, ok := services[sid]; !ok {
				appendFinding(&findings, sc.ScenarioID, sid, "UNKNOWN_CALLER", "", kind, seq)
				continue
			}
			services[sid].caps[ev.Capability] = struct{}{}
		case "SERVICE_CALL":
			caller := ev.CallerID
			callee := ev.CalleeID
			if _, ok := services[callee]; !ok {
				appendFinding(&findings, sc.ScenarioID, callee, "UNKNOWN_CALLEE", ev.Action, kind, seq)
				continue
			}
			if _, ok := services[caller]; !ok {
				appendFinding(&findings, sc.ScenarioID, caller, "UNKNOWN_CALLER", ev.Action, kind, seq)
				continue
			}
			callerCaps := services[caller].caps
			if !callerHasAny(callerCaps, ev.PropagatedCapabilities) && len(ev.PropagatedCapabilities) > 0 {
				appendFinding(&findings, sc.ScenarioID, caller, "PRIVILEGE_ESCALATION", ev.Action, ev.PropagatedCapabilities[0], seq)
			}
		}
	}

	edgeOut := make([]EdgeOut, 0)
	for key := range edges {
		parts := splitEdge(key)
		if len(parts) == 2 {
			edgeOut = append(edgeOut, EdgeOut{FromService: parts[0], ToService: parts[1]})
		}
	}
	sort.Slice(edgeOut, func(i, j int) bool {
		if edgeOut[i].FromService != edgeOut[j].FromService {
			return edgeOut[i].FromService < edgeOut[j].FromService
		}
		return edgeOut[i].ToService < edgeOut[j].ToService
	})

	outServices := make([]ServiceOut, 0, len(services))
	sids := make([]string, 0, len(services))
	for id := range services {
		sids = append(sids, id)
	}
	sort.Strings(sids)
	for _, id := range sids {
		st := services[id]
		outServices = append(outServices, ServiceOut{
			ServiceID:         id,
			Tier:              st.tier,
			Capabilities:      strSlice(st.caps),
			TrustBoundaryRisk: trustBoundaryRisk(st.tier),
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].FindingID < findings[j].FindingID
	})

	status := "VALID"
	if len(findings) > 0 {
		status = "INVALID"
	}

	return ScenarioOut{
		ScenarioID:             sc.ScenarioID,
		Status:                 status,
		DuplicateEventsSkipped: dupSkipped,
		Capture:                cap,
		PeerTrustEdges:         edgeOut,
		Services:               outServices,
		Findings:               findings,
	}
}

func splitEdge(key string) []string {
	for i := 0; i < len(key); i++ {
		if i+1 < len(key) && key[i] == '-' && key[i+1] == '>' {
			return []string{key[:i], key[i+2:]}
		}
	}
	return nil
}
