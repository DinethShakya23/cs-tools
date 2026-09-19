// Copyright (c) 2026 WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// elasticsearchPayload is the JSON body a Kibana rule's Webhook connector
// action sends, modeled to only the fields this adapter reads. rule_id and
// rule_name are Kibana's own Mustache-templated variables
// ({{rule.id}}/{{rule.name}}), not identifiers this adapter assigns.
type elasticsearchPayload struct {
	RuleName    string `json:"rule_name"`
	State       string `json:"state"` // "ACTIVE" | "COMPLETED" | "ERROR"
	AlertID     string `json:"alert_id"`
	Severity    string `json:"severity"` // numeric string, "1".."5"
	Service     string `json:"service"`
	Environment string `json:"environment"`
	Category    string `json:"category"`
}

// elasticsearchSeverityTable maps this vendor's own numeric 1-5 severity
// vocabulary onto this service's five-value vocabulary, only consulted for
// state "ACTIVE" — see mapElasticsearchPayload's state-override handling for
// "COMPLETED"/"ERROR", which bypass this table entirely.
var elasticsearchSeverityTable = map[string]string{
	"1": "critical",
	"2": "major",
	"3": "minor",
	"4": "warning",
	"5": "ok",
}

// elasticsearchDefaultService mirrors every other adapter's own
// fallback-service convention — AlertRequest.validate requires Service
// non-empty.
const elasticsearchDefaultService = "Managed Services"

// mapElasticsearchPayload parses a Kibana Webhook connector payload into an
// AlertRequest.
//
// State overrides severity, not the other way around:
//   - "ACTIVE": severity comes from elasticsearchSeverityTable, defaulting
//     to "ok" (this codebase's own established safe-default convention —
//     see openSearchSeverityTable's doc comment) for an unrecognized or
//     missing value.
//   - "COMPLETED": always "ok" — the condition cleared, regardless of
//     whatever severity value the payload still carries.
//   - "ERROR" (rule/monitor execution itself failed, a different condition
//     from the monitored system firing): always "critical" — a monitoring
//     pipeline failure needs attention even though nothing about the
//     underlying system state is known.
func mapElasticsearchPayload(body []byte) (AlertRequest, error) {
	var p elasticsearchPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return AlertRequest{}, fmt.Errorf("elasticsearch: %w", err)
	}

	var severity string
	switch strings.ToUpper(strings.TrimSpace(p.State)) {
	case "COMPLETED":
		severity = "ok"
	case "ERROR":
		severity = "critical"
	default: // "ACTIVE", or any other/missing value
		severity = "ok"
		if s, ok := elasticsearchSeverityTable[strings.TrimSpace(p.Severity)]; ok {
			severity = s
		}
	}

	service := p.Service
	if service == "" {
		service = elasticsearchDefaultService
	}

	ruleName := p.RuleName
	if ruleName == "" {
		ruleName = "Elasticsearch alert"
	}

	return AlertRequest{
		Source:      "elasticsearch",
		Severity:    severity,
		Service:     service,
		MetricName:  "Elasticsearch Alert: " + ruleName,
		Category:    p.Category,
		Environment: p.Environment,
		// alert_id is the value the prior ServiceNow-based pipeline matched
		// ACTIVE/COMPLETED states of the same alert against — sanitized
		// since this service embeds it in a "[group:...]" tag (see
		// sanitizeUniqueIdentifier's own doc comment); Kibana alert ids are
		// plain alphanumeric in practice, so this is defensive, not a fix
		// for a known colliding character.
		UniqueIdentifier: sanitizeUniqueIdentifier(p.AlertID),
		Description:      fmt.Sprintf("Elasticsearch/Kibana rule: %s\nState: %s", ruleName, p.State),
	}, nil
}

// CreateAlertFromElasticsearch handles POST /alerts/adapters/elasticsearch:
// translates a Kibana Webhook connector payload into this service's generic
// AlertRequest, then reuses enqueueAlert unchanged — same
// validation/buffering/worker/grouping/dedup/escalation path every other
// adapter in this file uses.
func (h *AlertHandler) CreateAlertFromElasticsearch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			writeError(w, http.StatusRequestEntityTooLarge, ErrMsgTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, errMsgReadBody)
		return
	}

	req, err := mapElasticsearchPayload(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, ErrMsgBadRequest)
		return
	}

	id, alertNumber, err := h.enqueueAlert(r.Context(), req)
	h.writeEnqueueResult(w, r, id, alertNumber, err)
}
