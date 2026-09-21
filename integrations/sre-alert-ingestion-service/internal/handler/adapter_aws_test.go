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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func cloudWatchSNSNotification(severity, newStateValue, alarmName string) []byte {
	descJSON, _ := json.Marshal(cloudWatchAlarmDescription{
		Service:     "Managed Cloud",
		Severity:    severity,
		Category:    "service_interruption",
		Environment: "Production",
	})
	alarm, _ := json.Marshal(cloudWatchAlarm{
		AlarmName:        alarmName,
		AlarmArn:         "arn:aws:cloudwatch:us-east-1:123456789012:alarm:" + alarmName,
		NewStateValue:    newStateValue,
		NewStateReason:   "Threshold Crossed",
		AlarmDescription: string(descJSON),
	})
	env, _ := json.Marshal(awsSNSEnvelope{Type: "Notification", Message: string(alarm)})
	return env
}

func TestMapCloudWatchAlarm_SeverityTable(t *testing.T) {
	cases := []struct {
		sev  string
		want string
	}{
		{"Critical", "critical"},
		{"Major", "major"},
		{"Minor", "minor"},
		{"Warning", "warning"},
		{"OK", "ok"},
		{"unrecognized", "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.sev, func(t *testing.T) {
			alarm := cloudWatchAlarm{
				AlarmName:        "high-cpu",
				NewStateValue:    "ALARM",
				AlarmDescription: `{"service":"svc","severity":"` + tc.sev + `"}`,
			}
			req := mapCloudWatchAlarm(alarm)
			if req.Severity != tc.want {
				t.Errorf("Severity = %q, want %q", req.Severity, tc.want)
			}
		})
	}
}

func TestMapCloudWatchAlarm_OKStateForcesOKRegardlessOfDescription(t *testing.T) {
	alarm := cloudWatchAlarm{
		AlarmName:        "high-cpu",
		NewStateValue:    "OK",
		AlarmDescription: `{"service":"svc","severity":"Critical"}`,
	}
	req := mapCloudWatchAlarm(alarm)
	if req.Severity != "ok" {
		t.Errorf("Severity = %q, want ok when NewStateValue is OK", req.Severity)
	}
}

func TestMapCloudWatchAlarm_UnparseableDescriptionDefaultsToOK(t *testing.T) {
	alarm := cloudWatchAlarm{
		AlarmName:        "high-cpu",
		NewStateValue:    "ALARM",
		AlarmDescription: `not json`,
	}
	req := mapCloudWatchAlarm(alarm)
	if req.Severity != "ok" {
		t.Errorf("Severity = %q, want ok (safe default) on an unparseable description", req.Severity)
	}
	if req.Service != awsDefaultService {
		t.Errorf("Service = %q, want fallback %q", req.Service, awsDefaultService)
	}
}

func TestMapCloudWatchAlarm_UniqueIdentifierIsSanitizedAlarmArn(t *testing.T) {
	alarm := cloudWatchAlarm{
		AlarmName:        "high-cpu",
		AlarmArn:         "arn:aws:cloudwatch:us-east-1:123456789012:alarm:high-cpu",
		NewStateValue:    "ALARM",
		AlarmDescription: `{"service":"svc","severity":"Critical"}`,
	}
	req := mapCloudWatchAlarm(alarm)
	want := "arn_aws_cloudwatch_us-east-1_123456789012_alarm_high-cpu"
	if req.UniqueIdentifier != want {
		t.Errorf("UniqueIdentifier = %q, want sanitized ARN %q", req.UniqueIdentifier, want)
	}
	// The sanitized form must itself pass validate()'s own delimiter check --
	// the whole point of sanitizing it.
	if req.UniqueIdentifier != sanitizeUniqueIdentifier(alarm.AlarmArn) {
		t.Errorf("UniqueIdentifier does not match sanitizeUniqueIdentifier's own output")
	}
}

func TestCreateAlertFromAWS_MismatchedAuthenticatedSourceReturns403(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	body := cloudWatchSNSNotification("Critical", "ALARM", "high-cpu")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/aws", bytes.NewReader(body))
	r = withAuthenticatedUsername(r, "site24x7")
	w := httptest.NewRecorder()
	h.CreateAlertFromAWS(w, r)

	assertStatus(t, w, http.StatusForbidden)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called when the authenticated identity does not match this adapter's fixed source")
	}
}

func TestCreateAlertFromAWS_NoAuthenticatedUsernameReturns500(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	body := cloudWatchSNSNotification("Critical", "ALARM", "high-cpu")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/aws", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateAlertFromAWS(w, r)

	assertStatus(t, w, http.StatusInternalServerError)
	assertErrorMessage(t, w, ErrMsgInternal)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called when there is no authenticated identity in context")
	}
}

func TestCreateAlertFromAWS_NotificationSuccess(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	body := cloudWatchSNSNotification("Critical", "ALARM", "high-cpu")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/aws", bytes.NewReader(body))
	r = withAuthenticatedUsername(r, "aws")
	w := httptest.NewRecorder()
	h.CreateAlertFromAWS(w, r)

	assertStatus(t, w, http.StatusAccepted)
	if len(store.enqueuedPayloads) != 1 {
		t.Fatalf("Enqueue called %d times, want 1", len(store.enqueuedPayloads))
	}
}

func TestCreateAlertFromAWS_SubscriptionConfirmationConfirmsAndDoesNotEnqueue(t *testing.T) {
	var confirmedURL string
	orig := awsSubscriptionConfirmGet
	awsSubscriptionConfirmGet = func(url string) (*http.Response, error) {
		confirmedURL = url
		return &http.Response{Body: http.NoBody, StatusCode: http.StatusOK}, nil
	}
	defer func() { awsSubscriptionConfirmGet = orig }()

	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	env, _ := json.Marshal(awsSNSEnvelope{
		Type:         "SubscriptionConfirmation",
		SubscribeURL: "https://sns.us-east-1.amazonaws.com/confirm?token=abc",
	})
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/aws", bytes.NewReader(env))
	r = withAuthenticatedUsername(r, "aws")
	w := httptest.NewRecorder()
	h.CreateAlertFromAWS(w, r)

	assertStatus(t, w, http.StatusOK)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called for a subscription confirmation")
	}
	if confirmedURL != "https://sns.us-east-1.amazonaws.com/confirm?token=abc" {
		t.Errorf("confirmedURL = %q, want the SubscribeURL to be GETed", confirmedURL)
	}
}

func TestCreateAlertFromAWS_SubscriptionConfirmationStillReturns200OnGetFailure(t *testing.T) {
	orig := awsSubscriptionConfirmGet
	awsSubscriptionConfirmGet = func(url string) (*http.Response, error) {
		return nil, errors.New("connection refused")
	}
	defer func() { awsSubscriptionConfirmGet = orig }()

	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	env, _ := json.Marshal(awsSNSEnvelope{
		Type:         "SubscriptionConfirmation",
		SubscribeURL: "https://sns.us-east-1.amazonaws.com/confirm?token=abc",
	})
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/aws", bytes.NewReader(env))
	r = withAuthenticatedUsername(r, "aws")
	w := httptest.NewRecorder()
	h.CreateAlertFromAWS(w, r)

	// A failed confirmation GET is an AWS-side problem, not something
	// retrying this webhook call fixes -- still 200.
	assertStatus(t, w, http.StatusOK)
}

func TestCreateAlertFromAWS_UnsubscribeConfirmationAcknowledgedNoEnqueue(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	env, _ := json.Marshal(awsSNSEnvelope{Type: "UnsubscribeConfirmation"})
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/aws", bytes.NewReader(env))
	r = withAuthenticatedUsername(r, "aws")
	w := httptest.NewRecorder()
	h.CreateAlertFromAWS(w, r)

	assertStatus(t, w, http.StatusOK)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called for an unsubscribe confirmation")
	}
}

func TestCreateAlertFromAWS_MalformedBodyReturns400(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/aws", bytes.NewReader([]byte(`not json`)))
	r = withAuthenticatedUsername(r, "aws")
	w := httptest.NewRecorder()
	h.CreateAlertFromAWS(w, r)

	assertStatus(t, w, http.StatusBadRequest)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called for a malformed body")
	}
}

func TestCreateAlertFromAWS_MalformedMessageReturns400(t *testing.T) {
	store := &mockStore{}
	h := NewAlertHandler(store, "caller-1", "")

	env, _ := json.Marshal(awsSNSEnvelope{Type: "Notification", Message: "not json"})
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/aws", bytes.NewReader(env))
	r = withAuthenticatedUsername(r, "aws")
	w := httptest.NewRecorder()
	h.CreateAlertFromAWS(w, r)

	assertStatus(t, w, http.StatusBadRequest)
	if len(store.enqueuedPayloads) != 0 {
		t.Error("Enqueue should not be called for a malformed alarm message")
	}
}

func TestCreateAlertFromAWS_StoreFailureReturns500(t *testing.T) {
	store := &mockStore{enqueueFn: func(ctx context.Context, id string, buildPayload func(string) ([]byte, error)) (string, error) {
		return "", errors.New("connection refused")
	}}
	h := NewAlertHandler(store, "caller-1", "")

	body := cloudWatchSNSNotification("Critical", "ALARM", "high-cpu")
	r := httptest.NewRequest(http.MethodPost, "/alerts/adapters/aws", bytes.NewReader(body))
	r = withAuthenticatedUsername(r, "aws")
	w := httptest.NewRecorder()
	h.CreateAlertFromAWS(w, r)

	assertStatus(t, w, http.StatusInternalServerError)
	assertErrorMessage(t, w, ErrMsgInternal)
}
