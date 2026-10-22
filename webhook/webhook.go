// Package webhook receives AssessMatrix webhooks: it checks the signature,
// decodes the event and hands it to your code.
//
//	http.Handle("/hooks/assessmatrix", webhook.Handler(func(ctx context.Context, e *webhook.Event) error {
//		if seen(e.ID) { // the same event can arrive more than once
//			return nil
//		}
//		switch e.Type {
//		case webhook.AttemptSubmitted:
//			a, err := e.Attempt()
//			...
//		}
//		return nil
//	}, secret))
//
// Delivery is at least once and not ordered: de-duplicate on Event.ID and
// order by Event.CreatedAt. Payloads name records by id only; fetch anything
// else through the API.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Event types.
const (
	ExamPublished     = "exam.published"
	AssignmentInvited = "assignment.invited"
	AttemptStarted    = "attempt.started"
	AttemptSubmitted  = "attempt.submitted"
	AttemptExpired    = "attempt.expired"
	AttemptScored     = "attempt.scored"
	CredentialIssued  = "credential.issued"
	CredentialRevoked = "credential.revoked"
	Ping              = "webhook.ping"
)

// Headers on every delivery.
const (
	HeaderSignature = "AssessMatrix-Signature"
	HeaderEventID   = "AssessMatrix-Event-Id"
	HeaderEventType = "AssessMatrix-Event-Type"
	HeaderDelivery  = "AssessMatrix-Delivery-Id"
)

// Tolerance is how far a signature's time may be from now. Older requests
// are refused, so a captured one cannot be replayed later.
const Tolerance = 5 * time.Minute

// MaxBody bounds what Parse reads. Payloads carry ids and scores only.
const MaxBody = 1 << 20

// ErrSignature is a request whose signature is missing, wrong or too old.
var ErrSignature = errors.New("webhook: bad signature")

// Event is one delivery's body.
type Event struct {
	// The same on every retry and redelivery: de-duplicate on it.
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	CreatedAt time.Time       `json:"created_at"`
	Data      json.RawMessage `json:"data"`
}

// Score is an attempt's result when it carries one.
type Score struct {
	Pct    int32 `json:"pct"`
	Points int32 `json:"points"`
	Max    int32 `json:"max"`
	Passed bool  `json:"passed"`
	// Essays still wait for a person to score them.
	PendingReview bool `json:"pending_review"`
}

// Attempt is the data of every attempt.* event.
type Attempt struct {
	AttemptID    string     `json:"attempt_id"`
	AssignmentID string     `json:"assignment_id"`
	ExamID       string     `json:"exam_id"`
	ExamVersion  int32      `json:"exam_version"`
	PersonID     string     `json:"person_id"`
	StartedAt    time.Time  `json:"started_at"`
	DeadlineAt   *time.Time `json:"deadline_at,omitempty"`
	SubmittedAt  *time.Time `json:"submitted_at,omitempty"`
	// Set once the attempt is handed in or scored.
	Score *Score `json:"score,omitempty"`
}

// Exam is the data of exam.published.
type Exam struct {
	ExamID  string `json:"exam_id"`
	Version int32  `json:"version"`
	// EXAM_KIND_* as the API names it.
	Kind  string `json:"kind"`
	Title string `json:"title"`
}

// Invitation is the data of assignment.invited. The link itself is never
// sent: it opens the candidate's paper.
type Invitation struct {
	AssignmentID string `json:"assignment_id"`
	ExamID       string `json:"exam_id"`
	ExamVersion  int32  `json:"exam_version"`
	PersonID     string `json:"person_id"`
	// Why it was mailed: the first send, a resend, or the candidate asked
	// for a new link.
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Credential is the data of credential.issued and credential.revoked.
type Credential struct {
	CredentialID string `json:"credential_id"`
	AttemptID    string `json:"attempt_id"`
	ExamID       string `json:"exam_id"`
	PersonID     string `json:"person_id"`
	// The public verification page.
	URL string `json:"url"`
	// credential.issued: an earlier revocation was undone.
	Restored bool `json:"restored,omitempty"`
	// credential.revoked: why.
	Reason string `json:"reason,omitempty"`
}

// Attempt decodes the data of an attempt.* event.
func (e *Event) Attempt() (*Attempt, error) {
	var a Attempt
	return &a, e.decodeAs("attempt.", &a)
}

// Exam decodes the data of exam.published.
func (e *Event) Exam() (*Exam, error) {
	var x Exam
	return &x, e.decodeAs(ExamPublished, &x)
}

// Invitation decodes the data of assignment.invited.
func (e *Event) Invitation() (*Invitation, error) {
	var i Invitation
	return &i, e.decodeAs(AssignmentInvited, &i)
}

// Credential decodes the data of a credential.* event.
func (e *Event) Credential() (*Credential, error) {
	var c Credential
	return &c, e.decodeAs("credential.", &c)
}

// decodeAs decodes Data into v if the event's type starts with prefix.
func (e *Event) decodeAs(prefix string, v any) error {
	if !strings.HasPrefix(e.Type, prefix) {
		return fmt.Errorf("webhook: cannot decode %s as %s", e.Type, strings.TrimSuffix(prefix, "."))
	}
	if err := json.Unmarshal(e.Data, v); err != nil {
		return fmt.Errorf("webhook: decode %s: %w", e.Type, err)
	}
	return nil
}

// Decode unmarshals the event's data into v, for event types without a
// helper here.
func (e *Event) Decode(v any) error { return json.Unmarshal(e.Data, v) }

// Sign returns the signature header the server sends for body at t. Useful
// for testing a receiver.
func Sign(secret string, t time.Time, body []byte) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	return "t=" + ts + ",v1=" + mac(secret, ts, body)
}

func mac(secret, ts string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// Verify reports whether header is a valid signature of body by secret,
// made within Tolerance of now.
func Verify(secret, header string, body []byte, now time.Time) bool {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sig == "" || secret == "" {
		return false
	}
	if d := now.Sub(time.Unix(sec, 0)); d > Tolerance || d < -Tolerance {
		return false
	}
	return hmac.Equal([]byte(mac(secret, ts, body)), []byte(sig))
}

// Parse reads, verifies and decodes a delivery. It returns ErrSignature
// when the request was not signed with secret.
func Parse(r *http.Request, secret string) (*Event, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("webhook: read body: %w", err)
	}
	if len(body) > MaxBody {
		return nil, errors.New("webhook: body too large")
	}
	if !Verify(secret, r.Header.Get(HeaderSignature), body, time.Now()) {
		return nil, ErrSignature
	}
	var e Event
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("webhook: decode body: %w", err)
	}
	return &e, nil
}

// Handler answers deliveries: 401 for a bad signature, 400 for a body that
// does not decode, 500 when fn fails (so the server tries again later) and
// 204 when it succeeds. Pass more than one secret while rotating, newest
// first; any of them is accepted.
func Handler(fn func(context.Context, *Event) error, secrets ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
		if err != nil || len(body) > MaxBody {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		sig, now := r.Header.Get(HeaderSignature), time.Now()
		ok := false
		for _, s := range secrets {
			if Verify(s, sig, body, now) {
				ok = true
				break
			}
		}
		if !ok {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		var e Event
		if err := json.Unmarshal(body, &e); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if err := fn(r.Context(), &e); err != nil {
			http.Error(w, "not processed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
