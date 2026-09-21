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
	"log/slog"
	"net/http"
	"strings"
)

// awsSNSEnvelope is the outer SNS message envelope AWS wraps every
// CloudWatch alarm notification in. Type distinguishes a real alarm
// notification from the two control messages SNS itself sends
// (SubscriptionConfirmation/UnsubscribeConfirmation) — see
// CreateAlertFromAWS's own branching.
type awsSNSEnvelope struct {
	Type         string `json:"Type"`
	MessageID    string `json:"MessageId"`
	SubscribeURL string `json:"SubscribeURL"`
	// Message carries the CloudWatch alarm as a JSON string (not a nested
	// object) — SNS's own wire format, not this adapter's choice.
	Message string `json:"Message"`
}

// cloudWatchAlarm is the CloudWatch alarm-state-change notification body,
// modeled to only the fields this adapter reads.
type cloudWatchAlarm struct {
	AlarmName      string `json:"AlarmName"`
	AlarmArn       string `json:"AlarmArn"`
	NewStateValue  string `json:"NewStateValue"`
	NewStateReason string `json:"NewStateReason"`
	// AlarmDescription carries operator-configured metadata as a JSON
	// string embedded in this free-text field — CloudWatch alarms have no
	// native custom-fields mechanism, so this is the only place mandatory
	// fields (service/severity/category/environment) can travel.
	AlarmDescription string `json:"AlarmDescription"`
}

// cloudWatchAlarmDescription is AlarmDescription's own JSON-string content,
// parsed separately since it arrives double-encoded.
type cloudWatchAlarmDescription struct {
	Service     string `json:"service"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Environment string `json:"environment"`
}

// awsSeverityTable maps this vendor's own Critical/Major/Minor/Warning/OK
// vocabulary (case-insensitive) onto this service's identical five-value
// vocabulary — effectively an identity map, kept as an explicit table (like
// every other adapter's own table) rather than a bare lowercase pass-through,
// so an unrecognized value is caught here, not left to
// internal/severity.MapImpactUrgency's own separate fallback.
var awsSeverityTable = map[string]string{
	"critical": "critical",
	"major":    "major",
	"minor":    "minor",
	"warning":  "warning",
	"ok":       "ok",
}

// awsDefaultService mirrors azureDefaultService's own fallback string and
// reasoning — AlertRequest.validate requires Service non-empty, and the
// AlarmDescription's own service field is exactly the kind of
// operator-configured value that can be missing.
const awsDefaultService = "Managed Services"

// awsSubscriptionConfirmGet performs the GET AWS SNS requires to complete a
// topic subscription handshake. A package-level var (not a method value) so
// tests can swap it for a stub without threading an HTTP client through
// AlertHandler's constructor — mirrors internal/csmclient's own
// tokenFetchTimeout swap-in-tests convention.
var awsSubscriptionConfirmGet = http.Get

// mapCloudWatchAlarm parses a CloudWatch alarm-state-change notification
// (already unwrapped from its SNS envelope) into an AlertRequest.
//
// Severity default: an unrecognized or unparseable AlarmDescription maps to
// "ok" (see awsSeverityTable's doc comment and openSearchSeverityTable's
// identical reasoning) — a deliberate improvement over the prior
// ServiceNow-based pipeline, which defaulted an unparseable description to
// Critical. Failing open to the *least* alarming classification, not the
// most, is this service's own established convention; see
// internal/handler's other adapters for the same choice.
//
// Recovery override: NewStateValue == "OK" always forces severity to "ok"
// regardless of what AlarmDescription's own severity field says — the same
// "a resolved condition is never still critical" override
// mapAzurePayload applies for that vendor's own resolved signal.
func mapCloudWatchAlarm(alarm cloudWatchAlarm) AlertRequest {
	var desc cloudWatchAlarmDescription
	// Parse failure leaves desc at its zero value — every field then falls
	// through to this function's own defaults below, not an error: a
	// malformed AlarmDescription must still produce a real, if
	// under-populated, alert (see this codebase's persist-before-attempt
	// philosophy — nothing here is a validation gate).
	_ = json.Unmarshal([]byte(alarm.AlarmDescription), &desc)

	severity := "ok"
	if s, ok := awsSeverityTable[strings.ToLower(strings.TrimSpace(desc.Severity))]; ok {
		severity = s
	}
	if strings.EqualFold(strings.TrimSpace(alarm.NewStateValue), "OK") {
		severity = "ok"
	}

	service := desc.Service
	if service == "" {
		service = awsDefaultService
	}

	metricName := alarm.AlarmName
	if metricName == "" {
		metricName = "CloudWatch alarm"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "CloudWatch alarm: %s\n", alarm.AlarmName)
	fmt.Fprintf(&b, "New state: %s\n", alarm.NewStateValue)
	if alarm.NewStateReason != "" {
		fmt.Fprintf(&b, "Reason: %s\n", alarm.NewStateReason)
	}

	return AlertRequest{
		Source:      "aws",
		Severity:    severity,
		Service:     service,
		MetricName:  metricName,
		Category:    desc.Category,
		Environment: desc.Environment,
		// CloudWatch Alarm ARN is the unique identifier the prior
		// ServiceNow-based pipeline used for this vendor too — stable per
		// alarm, present on every real notification. Sanitized: an ARN
		// always contains colons, which validate() forbids in
		// UniqueIdentifier (see sanitizeUniqueIdentifier's own doc comment).
		UniqueIdentifier: sanitizeUniqueIdentifier(alarm.AlarmArn),
		Description:      strings.TrimRight(b.String(), "\n"),
	}
}

// CreateAlertFromAWS handles POST /alerts/adapters/aws: AWS SNS's own
// envelope wraps every CloudWatch alarm notification, and also delivers two
// control message types this endpoint must handle without ever creating an
// alert from them:
//
//   - SubscriptionConfirmation: sent once, when the SNS topic is first
//     subscribed to this webhook. This handler auto-confirms it by GETing
//     SubscribeURL — matching the prior ServiceNow-based pipeline's own
//     "ServiceNow API automatically confirms SNS subscriptions" behavior —
//     and always responds 200 regardless of whether that GET succeeds,
//     since failure here is an AWS-side configuration problem, not
//     something retrying this webhook call fixes.
//   - UnsubscribeConfirmation: acknowledged, otherwise ignored.
//   - Notification (or any other/empty Type): the real case — Message
//     carries the CloudWatch alarm as a JSON string, parsed by
//     mapCloudWatchAlarm and enqueued exactly like every other vendor.
func (h *AlertHandler) CreateAlertFromAWS(w http.ResponseWriter, r *http.Request) {
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

	var env awsSNSEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeError(w, http.StatusBadRequest, ErrMsgBadRequest)
		return
	}

	switch env.Type {
	case "SubscriptionConfirmation":
		if env.SubscribeURL != "" {
			resp, err := awsSubscriptionConfirmGet(env.SubscribeURL)
			if err != nil {
				slog.ErrorContext(r.Context(), "aws: failed to confirm SNS subscription", "err", err)
			} else {
				_ = resp.Body.Close()
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "subscription_confirmation_handled"})
		return
	case "UnsubscribeConfirmation":
		writeJSON(w, http.StatusOK, map[string]string{"status": "unsubscribe_confirmation_acknowledged"})
		return
	}

	var alarm cloudWatchAlarm
	if err := json.Unmarshal([]byte(env.Message), &alarm); err != nil {
		writeError(w, http.StatusBadRequest, ErrMsgBadRequest)
		return
	}

	req := mapCloudWatchAlarm(alarm)

	if !h.requireAuthenticatedSource(w, r, req.Source) {
		return
	}

	id, alertNumber, err := h.enqueueAlert(r.Context(), req)
	h.writeEnqueueResult(w, r, id, alertNumber, err)
}
