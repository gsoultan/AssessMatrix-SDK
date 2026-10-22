package assessmatrix

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	v1 "github.com/gsoultan/assessmatrix-sdk/gen/assessmatrix/v1"
	"github.com/gsoultan/assessmatrix-sdk/gen/assessmatrix/v1/assessmatrixv1connect"
)

// fakeServer signs staff in the way the core does: a verified code or a
// tenant switch sets the am_staff cookie, and staff procedures read it.
type fakeServer struct {
	assessmatrixv1connect.UnimplementedAuthServiceHandler
	assessmatrixv1connect.UnimplementedTenantServiceHandler
	sessions map[string]*v1.Staff
}

func setCookie(h http.Header, value string, maxAge int) {
	h.Add("Set-Cookie", (&http.Cookie{Name: StaffCookie, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true,
		SameSite: http.SameSiteStrictMode}).String())
}

func (f *fakeServer) staff(h http.Header) (*v1.Staff, string, error) {
	r := http.Request{Header: h}
	c, err := r.Cookie(StaffCookie)
	if err == nil && f.sessions[c.Value] != nil {
		return f.sessions[c.Value], c.Value, nil
	}
	return nil, "", connect.NewError(connect.CodeUnauthenticated, errors.New("sign in required"))
}

func (f *fakeServer) VerifyStaffCode(_ context.Context, req *connect.Request[v1.VerifyStaffCodeRequest]) (*connect.Response[v1.VerifyStaffCodeResponse], error) {
	if req.Msg.GetCode() != "123456" {
		return connect.NewResponse(&v1.VerifyStaffCodeResponse{}), nil
	}
	s := &v1.Staff{Id: "s1", Email: req.Msg.GetEmail(), TenantId: "t1", Role: v1.Role_ROLE_ADMIN}
	f.sessions["tok-t1"] = s
	res := connect.NewResponse(&v1.VerifyStaffCodeResponse{Ok: true, Staff: s})
	setCookie(res.Header(), "tok-t1", 3600)
	return res, nil
}

func (f *fakeServer) WhoAmI(_ context.Context, req *connect.Request[v1.WhoAmIRequest]) (*connect.Response[v1.WhoAmIResponse], error) {
	s, _, err := f.staff(req.Header())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&v1.WhoAmIResponse{Staff: s}), nil
}

func (f *fakeServer) SignOut(_ context.Context, req *connect.Request[v1.SignOutRequest]) (*connect.Response[v1.SignOutResponse], error) {
	if _, tok, err := f.staff(req.Header()); err == nil {
		delete(f.sessions, tok)
	}
	res := connect.NewResponse(&v1.SignOutResponse{})
	setCookie(res.Header(), "", -1)
	return res, nil
}

func (f *fakeServer) SwitchTenant(_ context.Context, req *connect.Request[v1.SwitchTenantRequest]) (*connect.Response[v1.SwitchTenantResponse], error) {
	s, tok, err := f.staff(req.Header())
	if err != nil {
		return nil, err
	}
	delete(f.sessions, tok)
	next := &v1.Staff{Id: s.GetId(), Email: s.GetEmail(), TenantId: req.Msg.GetTenantId(), Role: v1.Role_ROLE_MEMBER}
	f.sessions["tok-"+req.Msg.GetTenantId()] = next
	res := connect.NewResponse(&v1.SwitchTenantResponse{Staff: next})
	setCookie(res.Header(), "tok-"+req.Msg.GetTenantId(), 3600)
	return res, nil
}

func newFake(t *testing.T) (*fakeServer, *httptest.Server) {
	f := &fakeServer{sessions: map[string]*v1.Staff{}}
	mux := http.NewServeMux()
	mux.Handle(assessmatrixv1connect.NewAuthServiceHandler(f))
	mux.Handle(assessmatrixv1connect.NewTenantServiceHandler(f))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func TestSignInSwitchSignOut(t *testing.T) {
	ctx := context.Background()
	_, srv := newFake(t)
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.WhoAmI(ctx); Code(err) != connect.CodeUnauthenticated {
		t.Fatalf("before sign-in: err = %v", err)
	}
	if _, err := c.VerifyCode(ctx, "ops@example.com", "000000"); !errors.Is(err, ErrCodeRejected) {
		t.Fatalf("wrong code: err = %v", err)
	}
	if _, err := c.VerifyCode(ctx, "ops@example.com", "123456"); err != nil {
		t.Fatal(err)
	}
	if s, err := c.WhoAmI(ctx); err != nil || s.GetTenantId() != "t1" {
		t.Fatalf("after sign-in: %v, %v", s, err)
	}
	if got := c.Session(); got != "tok-t1" {
		t.Fatalf("Session = %q", got)
	}

	if _, err := c.SwitchTenant(ctx, "t2"); err != nil {
		t.Fatal(err)
	}
	if s, err := c.WhoAmI(ctx); err != nil || s.GetTenantId() != "t2" {
		t.Fatalf("after switch: %v, %v", s, err)
	}

	if err := c.SignOut(ctx); err != nil {
		t.Fatal(err)
	}
	if c.Session() != "" {
		t.Fatal("session kept after sign-out")
	}
	if _, err := c.WhoAmI(ctx); Code(err) != connect.CodeUnauthenticated {
		t.Fatalf("after sign-out: err = %v", err)
	}
}

func TestWithSessionResumes(t *testing.T) {
	ctx := context.Background()
	f, srv := newFake(t)
	f.sessions["kept"] = &v1.Staff{Id: "s1", TenantId: "t1"}

	c, err := New(srv.URL+"/", WithSession("kept"))
	if err != nil {
		t.Fatal(err)
	}
	if s, err := c.WhoAmI(ctx); err != nil || s.GetId() != "s1" {
		t.Fatalf("resumed session: %v, %v", s, err)
	}
}

func TestWithHTTPClientIsNotModified(t *testing.T) {
	hc := &http.Client{}
	if _, err := New("https://assess.example.com", WithHTTPClient(hc)); err != nil {
		t.Fatal(err)
	}
	if hc.Jar != nil {
		t.Fatal("New set a cookie jar on the caller's http.Client")
	}
}

func TestNewRefusesBadURL(t *testing.T) {
	for _, u := range []string{"", "assess.example.com", "ftp://assess.example.com", "https://"} {
		if _, err := New(u); err == nil {
			t.Errorf("New(%q) accepted", u)
		}
	}
}
