#!/usr/bin/env bash
set -euo pipefail

cd /app

cat > /app/internal/capture/decode.go <<'DECODE_EOF'
package capture

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"os"

	"trustaudit/internal/replay"
)

type Stats struct {
	FormatVersion   int `json:"format_version"`
	RecordsTotal    int `json:"records_total"`
	RecordsValid    int `json:"records_valid"`
	RecordsRejected int `json:"records_rejected"`
	DupSeqRejects   int `json:"dup_seq_rejects"`
	TruncatedTail   int `json:"truncated_tail"`
	PayloadBytes    int `json:"payload_bytes"`
}

func Decode(path string) ([]replay.Event, Stats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, Stats{}, err
	}
	if len(data) < 8 || string(data[:4]) != "PCM1" {
		return nil, Stats{}, errors.New("bad magic")
	}
	formatVersion := int(binary.LittleEndian.Uint32(data[4:8]))
	stats := Stats{FormatVersion: formatVersion}
	if formatVersion != 1 {
		return nil, stats, errors.New("unsupported format_version")
	}
	off := 8
	seen := make(map[uint32]struct{})
	events := make([]replay.Event, 0)
	for off < len(data) {
		if off+12 > len(data) {
			stats.RecordsRejected++
			stats.TruncatedTail = 1
			break
		}
		recordSeq := binary.LittleEndian.Uint32(data[off : off+4])
		flags := binary.LittleEndian.Uint16(data[off+4 : off+6])
		reserved := binary.LittleEndian.Uint16(data[off+6 : off+8])
		payloadLen := binary.LittleEndian.Uint32(data[off+8 : off+12])
		off += 12
		stats.RecordsTotal++
		reason := ""
		if reserved != 0 {
			reason = "BAD_RESERVED"
		} else if flags != 0 {
			reason = "BAD_FLAGS"
		} else if payloadLen > 4096 {
			reason = "LEN_OVERFLOW"
		} else if _, ok := seen[recordSeq]; ok {
			reason = "DUP_SEQ"
		}
		if reason == "LEN_OVERFLOW" {
			if off+int(payloadLen)+4 <= len(data) {
				off += int(payloadLen) + 4
				stats.RecordsRejected++
				seen[recordSeq] = struct{}{}
				continue
			}
			stats.RecordsRejected++
			stats.TruncatedTail = 1
			break
		}
		if off+int(payloadLen)+4 > len(data) {
			stats.RecordsRejected++
			stats.TruncatedTail = 1
			break
		}
		payload := data[off : off+int(payloadLen)]
		off += int(payloadLen)
		checksum := binary.LittleEndian.Uint32(data[off : off+4])
		off += 4
		if reason == "" {
			hdr := make([]byte, 12)
			binary.LittleEndian.PutUint32(hdr[0:4], recordSeq)
			binary.LittleEndian.PutUint16(hdr[4:6], flags)
			binary.LittleEndian.PutUint16(hdr[6:8], reserved)
			binary.LittleEndian.PutUint32(hdr[8:12], payloadLen)
			if crc32.ChecksumIEEE(append(hdr, payload...)) != checksum {
				reason = "BAD_CRC"
			}
		}
		seen[recordSeq] = struct{}{}
		if reason != "" {
			stats.RecordsRejected++
			if reason == "DUP_SEQ" {
				stats.DupSeqRejects++
			}
			continue
		}
		var ev replay.Event
		if err := json.Unmarshal(payload, &ev); err != nil {
			stats.RecordsRejected++
			continue
		}
		stats.RecordsValid++
		stats.PayloadBytes += int(payloadLen)
		events = append(events, ev)
	}
	return events, stats, nil
}
DECODE_EOF

cat > /app/internal/replay/replay.go <<'EOF'
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
	tier string
	caps map[string]struct{}
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

func edgeKey(from, to string) string {
	return from + "\x00" + to
}

func hasEdge(edges map[string]struct{}, from, to string) bool {
	_, ok := edges[edgeKey(from, to)]
	return ok
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

func firstMissingProp(caps map[string]struct{}, propagated []string) string {
	missing := make([]string, 0)
	for _, p := range propagated {
		if _, ok := caps[p]; !ok {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	if len(missing) == 0 {
		return ""
	}
	return missing[0]
}

func Analyze(sc Scenario, cap CaptureOut) ScenarioOut {
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

	services := make(map[string]*serviceState)
	edges := make(map[string]struct{})
	findings := make([]Finding, 0)
	dupSkipped := 0
	seenEvent := make(map[string]struct{})
	privEscFlagged := make(map[string]struct{})
	maxSeq := 0

	events := append([]Event(nil), sc.Events...)
	sort.Slice(events, func(i, j int) bool {
		if events[i].Seq != events[j].Seq {
			return events[i].Seq < events[j].Seq
		}
		if events[i].ServiceID != events[j].ServiceID {
			return events[i].ServiceID < events[j].ServiceID
		}
		return events[i].EventID < events[j].EventID
	})

	for _, ev := range events {
		seq := ev.Seq
		if seq > maxSeq {
			maxSeq = seq
		}
		kind := ev.Kind
		if ev.EventID != "" {
			if _, dup := seenEvent[ev.EventID]; dup {
				dupSkipped++
				continue
			}
			seenEvent[ev.EventID] = struct{}{}
		}

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
			key := edgeKey(from, to)
			if _, exists := edges[key]; exists {
				appendFinding(&findings, sc.ScenarioID, to, "DUPLICATE_TRUST", "", from, seq)
				continue
			}
			edges[key] = struct{}{}
		case "REVOKE_TRUST":
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
			delete(edges, edgeKey(from, to))
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
			action := ev.Action
			calleeSt, ok := services[callee]
			if !ok {
				appendFinding(&findings, sc.ScenarioID, callee, "UNKNOWN_CALLEE", action, kind, seq)
				continue
			}
			callerSt, ok := services[caller]
			if !ok {
				appendFinding(&findings, sc.ScenarioID, caller, "UNKNOWN_CALLER", action, kind, seq)
				continue
			}
			if !hasEdge(edges, caller, callee) {
				appendFinding(&findings, sc.ScenarioID, callee, "UNTRUSTED_PEER", action, caller, seq)
				continue
			}
			if blockPartner && callerSt.tier == "partner" && calleeSt.tier == "privileged" {
				appendFinding(&findings, sc.ScenarioID, caller, "RESTRICTED_ESCALATION", action, callee, seq)
				continue
			}
			if requireToken && calleeSt.tier == "internal" && !ev.HasToken {
				appendFinding(&findings, sc.ScenarioID, callee, "UNVERIFIED_CALLER", action, "", seq)
				continue
			}
			if miss := firstMissingProp(callerSt.caps, ev.PropagatedCapabilities); miss != "" {
				pkey := caller + "::" + miss
				if _, done := privEscFlagged[pkey]; !done {
					privEscFlagged[pkey] = struct{}{}
					appendFinding(&findings, sc.ScenarioID, caller, "PRIVILEGE_ESCALATION", action, miss, seq)
				}
			}
			orig := ev.OriginalCaller
			if orig != "" && orig != caller {
				if miss := firstMissingProp(callerSt.caps, ev.PropagatedCapabilities); miss != "" {
					appendFinding(&findings, sc.ScenarioID, orig, "LATERAL_MOVEMENT", action, miss, seq)
				}
			}
		}
	}

	auditSeq := maxSeq + 1
	meshFlagged := make(map[string]struct{})
	openFlagged := make(map[string]struct{})

	for key := range edges {
		parts := splitEdgeKey(key)
		if len(parts) != 2 {
			continue
		}
		from, to := parts[0], parts[1]
		fromSt, ok1 := services[from]
		toSt, ok2 := services[to]
		if !ok1 || !ok2 {
			continue
		}
		if fromSt.tier == "partner" && toSt.tier == "internal" {
			mkey := from + "::" + to
			if _, done := meshFlagged[mkey]; done {
				continue
			}
			if !hasEdge(edges, to, from) {
				meshFlagged[mkey] = struct{}{}
				appendFinding(&findings, sc.ScenarioID, to, "MESH_ASYMMETRY", "", from, auditSeq)
			}
		}
	}

	for sid, st := range services {
		if st.tier != "privileged" {
			continue
		}
		if _, ok := st.caps["mesh:audit"]; ok {
			continue
		}
		partners := make([]string, 0)
		for key := range edges {
			parts := splitEdgeKey(key)
			if len(parts) != 2 {
				continue
			}
			from, to := parts[0], parts[1]
			if to != sid {
				continue
			}
			if fs, ok := services[from]; ok && fs.tier == "partner" {
				partners = append(partners, from)
			}
		}
		if len(partners) == 0 {
			continue
		}
		sort.Strings(partners)
		if _, done := openFlagged[sid]; !done {
			openFlagged[sid] = struct{}{}
			appendFinding(&findings, sc.ScenarioID, sid, "OPEN_PRIVILEGE_PATH", "", partners[0], auditSeq)
		}
	}

	for sid, st := range services {
		if st.tier == "privileged" {
			if _, ok := st.caps["mesh:admin"]; !ok {
				appendFinding(&findings, sc.ScenarioID, sid, "ADMIN_UNBOUND", "", "", auditSeq)
			}
		}
	}

	edgeOut := make([]EdgeOut, 0, len(edges))
	for key := range edges {
		parts := splitEdgeKey(key)
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

func splitEdgeKey(key string) []string {
	for i := 0; i < len(key); i++ {
		if key[i] == 0 {
			return []string{key[:i], key[i+1:]}
		}
	}
	return nil
}
EOF

make clean || true
make build
make run

wc -c /app/build/service_trust_boundary_report.json
