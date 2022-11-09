package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// Security365Provider represents  Identity Provider
type Security365Provider struct {
	*ProviderData
	RedirectURI string
}

var _ Provider = (*Security365Provider)(nil)

const Security365ProviderName = "Security365"

// NewSecurity365Provider initiates a new Security365Provider
func NewSecurity365Provider(p *ProviderData) *Security365Provider {
	p.ProviderName = Security365ProviderName
	// p.getAuthorizationHeaderFunc = makeOIDCHeader
	return &Security365Provider{ProviderData: p}
}

// GetLoginURL overrides GetLoginURL to add the access_type and approval_prompt parameters
func (p *Security365Provider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	p.RedirectURI = redirectURI
	return p.Data().LoginURL.String()
}

func (p *Security365Provider) makeBasicBase64Encoded() string {
	base64Encoded := base64.StdEncoding.EncodeToString([]byte(p.Data().ClientID + ":" + p.Data().ClientSecret))
	return "Basic " + base64Encoded
}

func (p *Security365Provider) Redeem(ctx context.Context, _, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}

	providerData := p.Data()
	if providerData.ClientSecret == "" {
		return nil, errors.New("missing client secret")
	}
	authInfo := p.makeBasicBase64Encoded()
	redeemURL := p.Data().RedeemURL.String()

	params := url.Values{}
	params.Add("extra", p.Data().Extra)
	params.Add("redirect_uri", p.RedirectURI)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		Jwt          string `json:"jwt"`
	}
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

// EnrichSession finds additional policy and license , ztca information
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
