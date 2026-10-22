// Package assessmatrix is a Go client for an AssessMatrix server.
//
// The server speaks Connect RPC; every service is reachable through a Client
// as the generated Connect client, so nothing the studio can do is out of
// reach. What this package adds is the part every caller would otherwise
// write: the session cookie the server signs staff in with, sign-in by
// emailed code, and switching tenants.
//
//	c, _ := assessmatrix.New("https://assess.example.com")
//	_ = c.RequestCode(ctx, "ops@example.com")
//	staff, _ := c.VerifyCode(ctx, "ops@example.com", code)
//	exams, _ := c.Exams.ListExams(ctx, connect.NewRequest(&v1.ListExamsRequest{}))
//
// A Client holds one staff session, so it acts in one tenant at a time. Use
// one Client per tenant, or SwitchTenant between calls that are not
// concurrent.
package assessmatrix

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/gsoultan/assessmatrix-sdk/gen/assessmatrix/v1"
	"github.com/gsoultan/assessmatrix-sdk/gen/assessmatrix/v1/assessmatrixv1connect"
)

// Session cookies the server sets.
const (
	StaffCookie     = "am_staff"
	CandidateCookie = "am_candidate"
)

// StaffSessionTTL is how long a staff session lasts on the server.
const StaffSessionTTL = 12 * time.Hour

// ErrCodeRejected is a sign-in code the server did not accept: wrong, expired
// or already used. Ask for a new one.
var ErrCodeRejected = errors.New("assessmatrix: sign-in code not accepted")

// Client calls one AssessMatrix server as one staff member.
type Client struct {
	Auth        assessmatrixv1connect.AuthServiceClient
	Setup       assessmatrixv1connect.SetupServiceClient
	Tenants     assessmatrixv1connect.TenantServiceClient
	Exams       assessmatrixv1connect.ExamServiceClient
	People      assessmatrixv1connect.PersonServiceClient
	Assignments assessmatrixv1connect.AssignmentServiceClient
	Results     assessmatrixv1connect.ResultServiceClient
	Proctor     assessmatrixv1connect.ProctorServiceClient
	Webhooks    assessmatrixv1connect.WebhookServiceClient
	// Candidates is the API the candidate runner uses. It signs in with the
	// candidate's own link and code, never with a staff session.
	Candidates assessmatrixv1connect.CandidateServiceClient

	base *url.URL
	http *http.Client
}

type options struct {
	http    *http.Client
	connect []connect.ClientOption
	session string
}

// Option configures New.
type Option func(*options)

// WithHTTPClient sends requests through hc. Its Transport and Timeout are
// used; the Client keeps its own cookie jar unless hc already has one.
func WithHTTPClient(hc *http.Client) Option {
	return func(o *options) { o.http = hc }
}

// WithClientOptions passes options to every Connect client, such as
// connect.WithGRPC() or interceptors.
func WithClientOptions(opts ...connect.ClientOption) Option {
	return func(o *options) { o.connect = append(o.connect, opts...) }
}

// WithSession starts the Client signed in with a staff session token kept
// from an earlier Session call.
func WithSession(token string) Option {
	return func(o *options) { o.session = token }
}

// New returns a Client for the server at baseURL, such as
// https://assess.example.com. Plain http is meant for a local server only:
// a production server sets Secure cookies, which are never sent over http.
func New(baseURL string, opts ...Option) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, fmt.Errorf("assessmatrix: base URL must be http(s)://host, got %q", baseURL)
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	hc := &http.Client{}
	if o.http != nil {
		copied := *o.http
		hc = &copied
	}
	if hc.Jar == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
		hc.Jar = jar
	}
	c := &Client{base: base, http: hc}
	if o.session != "" {
		c.SetSession(o.session)
	}
	u, co := base.String(), o.connect
	c.Auth = assessmatrixv1connect.NewAuthServiceClient(hc, u, co...)
	c.Setup = assessmatrixv1connect.NewSetupServiceClient(hc, u, co...)
	c.Tenants = assessmatrixv1connect.NewTenantServiceClient(hc, u, co...)
	c.Exams = assessmatrixv1connect.NewExamServiceClient(hc, u, co...)
	c.People = assessmatrixv1connect.NewPersonServiceClient(hc, u, co...)
	c.Assignments = assessmatrixv1connect.NewAssignmentServiceClient(hc, u, co...)
	c.Results = assessmatrixv1connect.NewResultServiceClient(hc, u, co...)
	c.Proctor = assessmatrixv1connect.NewProctorServiceClient(hc, u, co...)
	c.Webhooks = assessmatrixv1connect.NewWebhookServiceClient(hc, u, co...)
	c.Candidates = assessmatrixv1connect.NewCandidateServiceClient(hc, u, co...)
	return c, nil
}

// RequestCode asks the server to email a sign-in code to a staff address.
// The server answers the same way whether or not the address is known.
func (c *Client) RequestCode(ctx context.Context, email string) error {
	_, err := c.Auth.RequestStaffCode(ctx, connect.NewRequest(&v1.RequestStaffCodeRequest{Email: email}))
	return err
}

// VerifyCode signs in with an emailed code. On success the Client holds the
// session and every later call acts as the returned staff member, in the
// tenant the server signed them in to.
func (c *Client) VerifyCode(ctx context.Context, email, code string) (*v1.Staff, error) {
	res, err := c.Auth.VerifyStaffCode(ctx, connect.NewRequest(&v1.VerifyStaffCodeRequest{Email: email, Code: code}))
	if err != nil {
		return nil, err
	}
	if !res.Msg.GetOk() {
		return nil, ErrCodeRejected
	}
	return res.Msg.GetStaff(), nil
}

// WhoAmI returns the signed-in staff member, or an error with
// connect.CodeUnauthenticated when the session is missing or has ended.
func (c *Client) WhoAmI(ctx context.Context) (*v1.Staff, error) {
	res, err := c.Auth.WhoAmI(ctx, connect.NewRequest(&v1.WhoAmIRequest{}))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetStaff(), nil
}

// SwitchTenant ends this session and starts one in another tenant the staff
// member has access to. Calls in flight finish in the old tenant.
func (c *Client) SwitchTenant(ctx context.Context, tenantID string) (*v1.Staff, error) {
	res, err := c.Tenants.SwitchTenant(ctx, connect.NewRequest(&v1.SwitchTenantRequest{TenantId: tenantID}))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetStaff(), nil
}

// SignOut ends the session on the server and forgets it here.
func (c *Client) SignOut(ctx context.Context) error {
	_, err := c.Auth.SignOut(ctx, connect.NewRequest(&v1.SignOutRequest{}))
	if err == nil {
		c.SetSession("")
	}
	return err
}

// Session returns the staff session token, so a long-running service can
// keep it and pass it to WithSession after a restart. It is a bearer
// credential for the staff member: store it like a password. Empty when the
// Client is not signed in.
func (c *Client) Session() string {
	for _, ck := range c.http.Jar.Cookies(c.base) {
		if ck.Name == StaffCookie {
			return ck.Value
		}
	}
	return ""
}

// SetSession replaces the staff session token; empty forgets it.
func (c *Client) SetSession(token string) {
	ck := &http.Cookie{Name: StaffCookie, Value: token, Path: "/", Secure: c.base.Scheme == "https"}
	if token == "" {
		ck.MaxAge = -1
	}
	c.http.Jar.SetCookies(c.base, []*http.Cookie{ck})
}

// Code is the Connect code of an error a call returned, connect.CodeUnknown
// for one that did not come from the server.
func Code(err error) connect.Code { return connect.CodeOf(err) }
