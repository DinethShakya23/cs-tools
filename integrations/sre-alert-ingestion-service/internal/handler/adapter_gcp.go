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

// gcpPayload is GCP Cloud Monitoring's own webhook notification body,
// modeled to only the fields this adapter reads.
//
// Field names (condition_name, policy_user_labels, incident_id, state,
// severity) match GCP Cloud Monitoring's real incident webhook JSON shape,
// not the source review's own simplified conceptual example (a bare
// top-level "userLabels") — this hasn't been verified against a captured
// live payload, so treat this shape as the current best understanding, to
// confirm against a real GCP notification before depending on it in
// production.
type gcpPayload struct {
	Incident *gcpIncident `json:"incident"`
}

type gcpIncident struct {
	IncidentID       string            `json:"incident_id"`
	ConditionName    string            `json:"condition_name"`
	State            string            `json:"state"` // "open" | "closed"
	Severity         string            `json:"severity"`
	Summary          string            `json:"summary"`
	URL              string            `json:"url"`
	PolicyUserLabels map[string]string `json:"policy_user_labels"`
}

// gcpSeverityTable maps GCP's own severity vocabulary onto this service's
// five-value vocabulary. Unrecognized/missing values map to "ok" — this
// codebase's own established safe-default convention (see
// openSearchSeverityTable's doc comment), not the source review's own
// "closed (any severity) -> OK" special case alone, which is instead
// handled separately below via incident.state.
var gcpSeverityTable = map[string]string{
	"critical": "critical",
	"error":    "major",
	"warning":  "minor",
	"info":     "ok",
}

// gcpDefaultService mirrors every other adapter's own fallback-service
// convention — AlertRequest.validate requires Service non-empty.
const gcpDefaultService = "Managed Services"

// mapGCPPayload parses a GCP Cloud Monitoring webhook notification into an
// AlertRequest.
//
// Recovery override: incident.state == "closed" always forces severity to
// "ok" regardless of incident.severity — the same "a resolved condition is
// never still critical" override every other adapter in this file applies
// for its own vendor's equivalent signal.
func mapGCPPayload(body []byte) (AlertRequest, error) {
	var p gcpPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return AlertRequest{}, fmt.Errorf("gcp: %w", err)
	}
	if p.Incident == nil {
		return AlertRequest{}, fmt.Errorf("gcp: missing required incident")
	}
	inc := *p.Incident

	severity := "ok"
	if s, ok := gcpSeverityTable[strings.ToLower(strings.TrimSpace(inc.Severity))]; ok {
		severity = s
	}
	if strings.EqualFold(strings.TrimSpace(inc.State), "closed") {
		severity = "ok"
	}

	service := inc.PolicyUserLabels["service"]
	if service == "" {
		service = gcpDefaultService
	}

	metricName := inc.ConditionName
	if metricName == "" {
		metricName = "GCP Cloud Monitoring alert"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GCP alert condition: %s\n", inc.ConditionName)
	fmt.Fprintf(&b, "State: %s\n", inc.State)
	if inc.Summary != "" {
		fmt.Fprintf(&b, "Summary: %s\n", inc.Summary)
	}
	if inc.URL != "" {
		fmt.Fprintf(&b, "URL: %s\n", inc.URL)
	}

	return AlertRequest{
		Source:      "gcp",
		Severity:    severity,
		Service:     service,
		MetricName:  metricName,
		Category:    inc.PolicyUserLabels["category"],
		Environment: inc.PolicyUserLabels["environment"],
		// Sanitized: incident_id is a plain alphanumeric GCP identifier in
		// practice, but sanitizeUniqueIdentifier costs nothing to apply
		// defensively — see its own doc comment.
		UniqueIdentifier: sanitizeUniqueIdentifier(inc.IncidentID),
		Description:      strings.TrimRight(b.String(), "\n"),
	}, nil
}

// CreateAlertFromGCP handles POST /alerts/adapters/gcp: translates a GCP
// Cloud Monitoring webhook notification into this service's generic
// AlertRequest, then reuses enqueueAlert unchanged — same
// validation/buffering/worker/grouping/dedup/escalation path every other
// adapter in this file uses.
func (h *AlertHandler) CreateAlertFromGCP(w http.ResponseWriter, r *http.Request) {
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

	req, err := mapGCPPayload(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, ErrMsgBadRequest)
		return
	}

	id, alertNumber, err := h.enqueueAlert(r.Context(), req)
	h.writeEnqueueResult(w, r, id, alertNumber, err)
}
