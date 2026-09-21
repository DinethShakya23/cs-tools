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

// openObservePayload is the JSON body an OpenObserve alert's Webhook
// destination template sends, modeled to only the fields this adapter
// reads. Unlike every other vendor in this file, OpenObserve's own alert
// template already speaks numeric urgency/impact directly rather than a
// severity word — the source review's own field mapping section documents
// this template shape verbatim, not a native OpenObserve wire format this
// adapter reverse-engineered.
type openObservePayload struct {
	ShortDescription string `json:"short_description"`
	Description      string `json:"description"`
	Urgency          string `json:"urgency"` // numeric string, "1".."3"
	Impact           string `json:"impact"`  // numeric string, "1".."3", fallback when urgency is absent/unrecognized
	Service          string `json:"service"`
	Environment      string `json:"environment"`
	Category         string `json:"category"`
	// CorrelationID is this vendor's own dedup key — OpenObserve has no
	// native "resolved" event at all (see this adapter's own package doc
	// comment below), so correlation_id is the only stability guarantee
	// the source template gives for matching repeat notifications of the
	// same condition.
	CorrelationID string `json:"correlation_id"`
}

// openObserveSeverityTable maps this vendor's own numeric 1-3 urgency/
// impact vocabulary onto this service's five-value severity vocabulary.
// There is no native OK/resolved value in this vendor's own scale at all —
// see mapOpenObservePayload's own doc comment.
var openObserveSeverityTable = map[string]string{
	"1": "critical",
	"2": "major",
	"3": "minor",
}

// openObserveDefaultService mirrors every other adapter's own
// fallback-service convention — AlertRequest.validate requires Service
// non-empty.
const openObserveDefaultService = "Managed Services"

// mapOpenObservePayload parses an OpenObserve Webhook destination payload
// into an AlertRequest.
//
// No resolution/recovery override exists for this vendor, unlike every
// other adapter in this file: OpenObserve emits no native "resolved" event
// when a condition clears (the source review documents this as a known,
// accepted gap for this vendor — see this file's own doc comment on the
// prior ServiceNow-based pipeline's own mitigations: manual resolution, a
// mirrored inverse-condition alert, or a timer-based auto-close). This
// adapter does not invent one either.
//
// Severity: urgency is read first; impact is only consulted when urgency
// is absent or doesn't match a known value — matching the source review's
// own "urgency, falling back to impact" rule. An unrecognized or entirely
// missing value from both maps to "ok" (this codebase's own established
// safe-default convention — see openSearchSeverityTable's doc comment),
// not a fabricated worst-case guess.
func mapOpenObservePayload(body []byte) (AlertRequest, error) {
	var p openObservePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return AlertRequest{}, fmt.Errorf("openobserve: %w", err)
	}

	severity := "ok"
	if s, ok := openObserveSeverityTable[strings.TrimSpace(p.Urgency)]; ok {
		severity = s
	} else if s, ok := openObserveSeverityTable[strings.TrimSpace(p.Impact)]; ok {
		severity = s
	}

	service := p.Service
	if service == "" {
		service = openObserveDefaultService
	}

	metricName := p.ShortDescription
	if metricName == "" {
		metricName = "OpenObserve alert"
	}

	description := p.Description
	if description == "" {
		description = p.ShortDescription
	}

	return AlertRequest{
		Source:           "openobserve",
		Severity:         severity,
		Service:          service,
		MetricName:       metricName,
		Category:         p.Category,
		Environment:      p.Environment,
		UniqueIdentifier: sanitizeUniqueIdentifier(p.CorrelationID),
		Description:      description,
	}, nil
}

// CreateAlertFromOpenObserve handles POST /alerts/adapters/openobserve:
// translates an OpenObserve Webhook destination payload into this
// service's generic AlertRequest, then reuses enqueueAlert unchanged —
// same validation/buffering/worker/grouping/dedup/escalation path every
// other adapter in this file uses.
func (h *AlertHandler) CreateAlertFromOpenObserve(w http.ResponseWriter, r *http.Request) {
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

	req, err := mapOpenObservePayload(body)
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
