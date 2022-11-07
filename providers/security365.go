package providers

import (
	"bytes"
	"context"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// Security365Provider represents an Nextcloud based Identity Provider
type Security365Provider struct {
	*ProviderData
}

var _ Provider = (*Security365Provider)(nil)

const Security365ProviderName = "Security365"

// NewSecurity365Provider initiates a new Security365Provider
func NewSecurity365Provider(p *ProviderData) *Security365Provider {
	p.ProviderName = Security365ProviderName
	p.getAuthorizationHeaderFunc = makeOIDCHeader
	if p.EmailClaim == options.OIDCEmailClaim {
		// This implies the email claim has not been overridden, we should set a default
		// for this provider
		p.EmailClaim = "ocs.data.email"
	}
	return &Security365Provider{ProviderData: p}
}

func (p *Security365Provider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	// loginURL := makeLoginURL(p.Data(), redirectURI, state, extraParams)
	// return loginURL.String()
	return "https://devlogin.softcamp.co.kr/SCCloudOAuthService/authLogin?clientName=jyjungAuth2"
}

func (p *Security365Provider) Redeem(ctx context.Context, _, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}
	// redeemURL := p.RedeemURL.String()
	authInfo := "Basic ZTc3YWZmZmItZGYxNC00ZTBlLWIxOWQtNjlhNmJjN2MyYzUxOkp5a2hJeXdyS1NJdEtpWXBJU01pSWlRckppb3BKaUlrSWlvcUppb21JaXc="
	redeemURL := "https://devlogin.softcamp.co.kr/SCCloudOAuthService/common/oauth/token"
	params := url.Values{}
	params.Add("extra", "3CJ55MSE-xLO7Sxt4-qUBKzbcs-XP2cgGEq")
	params.Add("redirect_uri", "http://localhost:8080/oauth2/callback")
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	// Get the token from the body that we got from the token endpoint.

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		Jwt          string `json:"jwt"`
	}
	// err := requests.New(p.RedeemURL.String()).
	err := requests.New(redeemURL).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", authInfo).
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	session := &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		RefreshToken: jsonResponse.RefreshToken,
		Email:        "admin@socam.info",
	}

	session.CreatedAtNow()
	session.ExpiresIn(time.Duration(jsonResponse.ExpiresIn) * time.Second)

	return session, nil
}

func (p *Security365Provider) Validator(mail string) bool {
	return true
}

// EnrichSession finds additional policy and license information
func (p *Security365Provider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// profileURL := p.ValidateURL.String()
	// if p.ProfileURL.String() != "" {
	// 	profileURL = p.ProfileURL.String()
	// }

	// json, err := requests.New(profileURL).
	// 	WithContext(ctx).
	// 	SetHeader("Authorization", "Bearer "+s.AccessToken).
	// 	Do().
	// 	UnmarshalSimpleJSON()
	// if err != nil {
	// 	logger.Errorf("failed making request %v", err)
	// 	return err
	// }

	// groups, err := json.GetPath("ocs", "data", "groups").StringArray()
	// if err == nil {
	// 	for _, group := range groups {
	// 		if group != "" {
	// 			s.Groups = append(s.Groups, group)
	// 		}
	// 	}
	// }

	// user, err := json.GetPath("ocs", "data", "id").String()
	// if err != nil {
	// 	return fmt.Errorf("unable to extract id from userinfo endpoint: %v", err)
	// }
	// s.User = user

	// email, err := json.GetPath("ocs", "data", "email").String()
	// if err != nil {
	// 	return fmt.Errorf("unable to extract email from userinfo endpoint: %v", err)
	// }
	// s.Email = email
	return nil
}

// ValidateSession validates the AccessToken
func (p *Security365Provider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
