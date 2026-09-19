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

// icinga2Payload is the JSON body Icinga2's own NotificationCommand shell
// script POSTs, modeled to only the fields this adapter reads. A single
// payload shape covers both host-level and service-level notifications —
// ServiceName/ServiceState are empty on a host notification (the command
// template hardcodes them to "" — see this service's own source
// documentation for the exact shell command), HostState/ServiceState carry
// whichever check actually fired.
type icinga2Payload struct {
	NotificationType string      `json:"notification_type"` // "Problem" | "Acknowledgement" | "Recovery"
	HostName         string      `json:"host_name"`
	HostState        string      `json:"host_state"` // "UP" | "DOWN" | "UNREACHABLE"
	ServiceName      string      `json:"service_name"`
	ServiceState     string      `json:"service_state"` // "OK" | "WARNING" | "CRITICAL" | "UNKNOWN"
	ServiceOutput    string      `json:"service_output"`
	Vars             icinga2Vars `json:"vars"`
}

type icinga2Vars struct {
	Environment string `json:"environment"`
	Service     string `json:"service"`
	Category    string `json:"category"`
}

// icinga2ServiceSeverityTable maps Icinga2's own service-check state
// vocabulary onto this service's five-value severity vocabulary.
var icinga2ServiceSeverityTable = map[string]string{
	"critical": "critical",
	"warning":  "warning",
	"unknown":  "major",
	"ok":       "ok",
}

// icinga2HostSeverityTable maps Icinga2's own host-check state vocabulary
// onto this service's five-value severity vocabulary — a separate table
// from the service-check one since the two vocabularies (UP/DOWN/
// UNREACHABLE vs OK/WARNING/CRITICAL/UNKNOWN) don't overlap.
var icinga2HostSeverityTable = map[string]string{
	"down":        "critical",
	"unreachable": "major",
	"up":          "ok",
}

// icinga2DefaultService mirrors every other adapter's own fallback-service
// convention — AlertRequest.validate requires Service non-empty.
const icinga2DefaultService = "Managed Services"

// mapIcinga2Payload parses an Icinga2 notification payload into an
// AlertRequest.
//
// Recovery override: notification_type == "Recovery" always forces
// severity to "ok", regardless of the underlying host/service state value —
// the source review's own documented behavior for this vendor, and the same
// "a resolved condition is never still critical" pattern every other
// adapter in this file applies for its own vendor's equivalent signal.
//
// A service-level event (ServiceName non-empty) is distinguished from a
// host-level one by that field alone — Icinga2's own notification command
// templates always send an empty service_name/service_state pair for a
// host check.
func mapIcinga2Payload(body []byte) (AlertRequest, error) {
	var p icinga2Payload
	if err := json.Unmarshal(body, &p); err != nil {
		return AlertRequest{}, fmt.Errorf("icinga2: %w", err)
	}
	if strings.TrimSpace(p.HostName) == "" {
		return AlertRequest{}, fmt.Errorf("icinga2: missing required host_name")
	}

	isServiceCheck := p.ServiceName != ""

	severity := "ok"
	if isServiceCheck {
		if s, ok := icinga2ServiceSeverityTable[strings.ToLower(strings.TrimSpace(p.ServiceState))]; ok {
			severity = s
		}
	} else {
		if s, ok := icinga2HostSeverityTable[strings.ToLower(strings.TrimSpace(p.HostState))]; ok {
			severity = s
		}
	}
	if strings.EqualFold(strings.TrimSpace(p.NotificationType), "Recovery") {
		severity = "ok"
	}

	service := p.Vars.Service
	if service == "" {
		service = icinga2DefaultService
	}

	// "host!service" is Icinga/Nagios's own naming convention for a
	// service check, matching the prior ServiceNow-based pipeline's own
	// metric_name/unique_identifier value for this vendor (e.g.
	// "prod-server-01!http") — a bare host name for a host check, which
	// has no service component.
	identifier := p.HostName
	if isServiceCheck {
		identifier = p.HostName + "!" + p.ServiceName
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Icinga2 notification: %s\n", p.NotificationType)
	fmt.Fprintf(&b, "Host: %s (%s)\n", p.HostName, p.HostState)
	if isServiceCheck {
		fmt.Fprintf(&b, "Service: %s (%s)\n", p.ServiceName, p.ServiceState)
	}
	if p.ServiceOutput != "" {
		fmt.Fprintf(&b, "Output: %s", p.ServiceOutput)
	}

	return AlertRequest{
		Source:      "icinga2",
		Severity:    severity,
		Service:     service,
		MetricName:  identifier,
		Category:    p.Vars.Category,
		Environment: p.Vars.Environment,
		// Sanitized: identifier already avoids '[' ']' ':' in practice, but
		// applied defensively like every other adapter — see
		// sanitizeUniqueIdentifier's own doc comment.
		UniqueIdentifier: sanitizeUniqueIdentifier(identifier),
		Description:      strings.TrimRight(b.String(), "\n"),
	}, nil
}

// CreateAlertFromIcinga2 handles POST /alerts/adapters/icinga2: translates
// an Icinga2 NotificationCommand payload into this service's generic
// AlertRequest, then reuses enqueueAlert unchanged — same
// validation/buffering/worker/grouping/dedup/escalation path every other
// adapter in this file uses.
func (h *AlertHandler) CreateAlertFromIcinga2(w http.ResponseWriter, r *http.Request) {
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

	req, err := mapIcinga2Payload(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, ErrMsgBadRequest)
		return
	}

	id, alertNumber, err := h.enqueueAlert(r.Context(), req)
	h.writeEnqueueResult(w, r, id, alertNumber, err)
}
