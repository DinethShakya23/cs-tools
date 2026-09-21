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

// datadogPayload is the JSON body a Datadog Webhooks integration's custom
// payload template sends, modeled to only the fields this adapter reads.
// The template itself is operator-configured (one webhook per client/
// service, per the source review's own recommendation), not a fixed
// Datadog wire format — this shape matches that documented template
// exactly, field for field.
type datadogPayload struct {
	EventName   string `json:"event_name"`
	TriggerName string `json:"trigger_name"`
	Transition  string `json:"transition"` // e.g. "Triggered", "Recovered"
	AlertID     string `json:"alert_id"`
	Service     string `json:"service"`
	Category    string `json:"category"`
	// Tags is a comma-separated "key:value" list (bare tags without a
	// colon are ignored) — Datadog's own $TAGS webhook variable expands to
	// this, carrying env:<environment> and severity:<1-5> per monitor,
	// since Datadog has no first-class incident-severity/environment field
	// of its own to draw from directly.
	Tags string `json:"tags"`
}

// datadogSeverityTable maps this vendor's own numeric 1-5 severity tag
// vocabulary onto this service's five-value vocabulary.
var datadogSeverityTable = map[string]string{
	"1": "critical",
	"2": "major",
	"3": "minor",
	"4": "warning",
	"5": "ok",
}

// datadogDefaultService mirrors every other adapter's own fallback-service
// convention — AlertRequest.validate requires Service non-empty.
const datadogDefaultService = "Managed Services"

// parseDatadogTags splits a Datadog $TAGS string ("env:production,severity:1,other")
// into a key->value map. A bare tag with no colon is ignored — it carries
// no key this adapter can route on.
func parseDatadogTags(tags string) map[string]string {
	out := map[string]string{}
	for _, tag := range strings.Split(tags, ",") {
		tag = strings.TrimSpace(tag)
		key, value, ok := strings.Cut(tag, ":")
		if !ok || key == "" {
			continue
		}
		out[strings.ToLower(key)] = value
	}
	return out
}

// mapDatadogPayload parses a Datadog Webhooks payload into an AlertRequest.
//
// Recovery override: transition == "Recovered" always forces severity to
// "ok" regardless of the severity tag — the source review's own documented
// behavior for this vendor ("recovery forces OK regardless of the
// severity: tag"), and the same pattern every other adapter in this file
// applies for its own vendor's equivalent signal.
func mapDatadogPayload(body []byte) (AlertRequest, error) {
	var p datadogPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return AlertRequest{}, fmt.Errorf("datadog: %w", err)
	}

	tags := parseDatadogTags(p.Tags)

	severity := "ok"
	if s, ok := datadogSeverityTable[strings.TrimSpace(tags["severity"])]; ok {
		severity = s
	}
	if strings.EqualFold(strings.TrimSpace(p.Transition), "Recovered") {
		severity = "ok"
	}

	service := p.Service
	if service == "" {
		service = datadogDefaultService
	}

	metricName := p.EventName
	if metricName == "" {
		metricName = p.TriggerName
	}
	if metricName == "" {
		metricName = "Datadog alert"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Datadog monitor: %s\n", metricName)
	if p.TriggerName != "" && p.TriggerName != metricName {
		fmt.Fprintf(&b, "Query: %s\n", p.TriggerName)
	}
	fmt.Fprintf(&b, "Transition: %s", p.Transition)

	return AlertRequest{
		Source:      "datadog",
		Severity:    severity,
		Service:     service,
		MetricName:  metricName,
		Category:    p.Category,
		Environment: tags["env"],
		// alert_id (the Datadog monitor id) stays stable across a
		// Triggered/Recovered pair, matching the prior ServiceNow-based
		// pipeline's own dedup key for this vendor.
		UniqueIdentifier: sanitizeUniqueIdentifier(p.AlertID),
		Description:      strings.TrimRight(b.String(), "\n"),
	}, nil
}

// CreateAlertFromDatadog handles POST /alerts/adapters/datadog: translates
// a Datadog Webhooks integration payload into this service's generic
// AlertRequest, then reuses enqueueAlert unchanged — same
// validation/buffering/worker/grouping/dedup/escalation path every other
// adapter in this file uses.
func (h *AlertHandler) CreateAlertFromDatadog(w http.ResponseWriter, r *http.Request) {
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

	req, err := mapDatadogPayload(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, ErrMsgBadRequest)
		return
	}

	if !h.requireAuthenticatedSource(w, r, req.Source) {
		return
	}

	id, alertNumber, err := h.enqueueAlert(r.Context(), req)
	h.writeEnqueueResult(w, r, id, alertNumber, err)
}
