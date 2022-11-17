package providers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// Security365Provider represents  Identity Provider
type Security365Provider struct {
	*ProviderData
	RedirectURI string
	TokenURL    string
	RsaPubKey   *rsa.PublicKey
}

var _ Provider = (*Security365Provider)(nil)

const Security365ProviderName = "Security365"

// NewSecurity365Provider initiates a new Security365Provider
func NewSecurity365Provider(p *ProviderData) *Security365Provider {
	p.ProviderName = Security365ProviderName

	// Remove parameters that are not used by Security365
	// "--redeem-url",
	// "https://devlogin.softcamp.co.kr/SCCloudOAuthService/common/oauth/token",
	tokenUrl := p.LoginURL.Scheme + "://" + p.LoginURL.Host + "/SCCloudOAuthService/common/oauth/token"
	return &Security365Provider{
		ProviderData: p,
		TokenURL:     tokenUrl,
	}
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

/*
token's payload
{"reqAppId":"e77afffb-df14-4e0e-b19d-69a6bc7c2c51","reqAppName":"jyjungAuth2","companyId":"3CJ55MSE-xLO7Sxt4-qUBKzbcs-XP2cgGEq","ipAddress":"10.31.10.189","geoIp":{"countryName":null,"isoCode":null,"cityName":null,"postal":null,"state":null,"latitude":null,"longitude":null},"userAgent":{"operatingSystemName":"Windows NT","operatingSystemNameVersion":"Windows >=10","agentName":"Firefox","agentVersion":"106.0","deviceClass":"Desktop","deviceName":"Desktop","client":null},"user_name":"admin@socam.info","user_email":"admin@socam.info","authorities":["ADMIN","USER"],"userCustomProfile":"","openidInfo":{"AZURE":"1af21560-df4f-4e45-bff3-4f83ced33400"},"openidEmail":{"AZURE":"admin@socam.info"},"userRealName":"admin","appService":[{"appId":"06f60567-5b40-4ba4-8dd7-030493ecc9c4"},{"appId":"d7e09223-da0a-40dc-95ae-844771c0b2f6"},{"appId":"9c0cccf1-66e3-445c-b715-7dd19cc5a92a"},{"appId":"8cfcd2eb-20d1-4f54-90bc-68e76900c34e"},{"appId":"c56bc1bc-d96c-422f-b947-68101d4a26f2"},{"appId":"363481a1-02fa-4f2f-b252-7e6112dfd4a2"},{"appId":"a16764cd-2d27-4166-b98b-bda10fedb440"},{"appId":"f94e02e6-0873-4cd4-82a7-0da466b9736e"},{"appId":"efedc11f-4050-4baa-acd0-fe5256856651"},{"appId":"35233744-0029-4d83-b1c4-3366bd229b59"},{"appId":"2a3053b0-6097-46ec-b68a-97e09b63e1c6"},{"appId":"716bace6-439e-4daa-80fe-e6b5d80f098b"},{"appId":"e77afffb-df14-4e0e-b19d-69a6bc7c2c51"},{"appId":"9531c9c2-c3f7-4234-829b-03aab0668418"},{"appId":"87d4c845-ad66-4f09-86c5-5e67bd4d5645"},{"appId":"4e3b53b2-a18c-4d78-8de1-b9fcada4077c"}],"totalLoginCount":240,"exp":1668066912,"iat":1668063312}
*/

func (p *Security365Provider) Redeem(ctx context.Context, _, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}
	host := p.Data().LoginURL.Host
	extra := p.Data().Extra
	clientId := p.Data().ClientID
	clientSecret := p.Data().ClientSecret

	// Get Access Token from Security365
	accessToken, err := getSecurity365AccessToken(host, extra, clientId, clientSecret)
	if err != nil {
		return nil, err
	}

	// Get Public Key from Security365
	rsapubkey, err := getCompanyRSAPubKey(host, extra, accessToken)
	if err != nil {
		return nil, err
	}
	println(rsapubkey)

	providerData := p.Data()
	if providerData.ClientSecret == "" {
		return nil, errors.New("missing client secret")
	}
	authInfo := p.makeBasicBase64Encoded()
	params := url.Values{}
	params.Add("extra", extra)
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
	err = requests.New(p.TokenURL).
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

	jwtString := jsonResponse.Jwt
	parts := strings.Split(jwtString, ".")
	err = jwt.SigningMethodRS256.Verify(strings.Join(parts[0:2], "."), parts[2], rsapubkey)
	if err != nil {
		return nil, err
	}

	var security365JWT struct {
		UserEmail string `json:"user_email"`
		UserName  string `json:"user_name"`
	}

	jsonStr, err := getJWTDecodedPayload(jwtString)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(jsonStr), &security365JWT)
	if err != nil {
		return nil, err
	}

	session := &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		RefreshToken: jsonResponse.RefreshToken,
		Email:        security365JWT.UserEmail,
		User:         security365JWT.UserName,
		AllowPolicy:  "",
	}

	session.CreatedAtNow()
	session.ExpiresIn(time.Duration(jsonResponse.ExpiresIn) * time.Second)

	allowPolicy, denyPolicy, err := getCustomProfileInfo(host, extra, accessToken, security365JWT.UserName)
	if err == nil {
		session.AllowPolicy = allowPolicy
		session.DenyPolicy = denyPolicy
		// 전역으로 가지고 있는건 서비스가 리셋된 상태에서 세션이 남아 있을때 제어가 안되는 문제가 있다.
		// s := GetSecurity365RuleMgrInstance()
		// err = s.AddItem(security365JWT.UserName, userPolicy)
		// if err != nil {
		// 	return nil, err
		// }
	}

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

func makeBasicBase64Encoded(clientID, ClientSecret string) string {
	base64Encoded := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + ClientSecret))
	return "Basic " + base64Encoded
}

func getSecurity365AccessToken(domain, extra, clientID, clientSecret string) (string, error) {
	authInfo := makeBasicBase64Encoded(clientID, clientSecret)
	authUrl := "https://" + domain + "/SCCloudOAuthService/common/oauth/token"
	params := url.Values{}
	params.Add("extra", extra)
	params.Add("grant_type", "client_credentials")
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope"`
		Jwt         string `json:"jwt"`
	}

	err := requests.New(authUrl).
		WithContext(context.Background()).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("extra", extra).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", authInfo).
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return "", err
	}

	return jsonResponse.AccessToken, nil
}

/*
[
    {
        "companyId": "uFhoVIZI-wni6zwDS-E6xGXPqT-m2ms8GWh",
        "companyRSAPubKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyIOnG2asf5Rs5cmDo8K5ap8+zD4i/ZN9mfq79VfxUSaoFUG76w5cqrarerpHYGBVVIQvTSLQGl7EtVxJNvlilSJp08h0vJBTVClXDt6unbRBFhNM4tcetpbTVTPZF0awhREOO9K6TyWO1CeNFn82y9FKUCFn0a6ItDy1ryT/PBoh3VYsoiVZEdHTZ5tbPsTsMjvUkZh+9RUJLsPZbCwLnbvqLM9Dw18ncL/X+DcidjhYQYTbs1PyQGHMYyqi+5k3FhlrLIwiBj+9pjMOqikJ61v5OJcim95rlPJg7JruXiPGzfXVer/v/rCNlWG3LRH2dHoEmVWFzv+RYzHZuoM+7QIDAQAB",
        "companyRSAPriKey": null
    }
]
*/
func getCompanyRSAPubKeyPemString(domain, extra, accessToken string) (string, error) {
	type Security365Pub struct {
		CompanyId        string `json:"companyId"`
		CompanyRSAPubKey string `json:"companyRSAPubKey"`
		CompanyRSAPriKey string `json:"companyRSAPriKey"`
	}

	var pubKeys []Security365Pub
	pubkeyUrl := "https://" + domain + "/SCCloudOAuthService/" + extra + "/company/getCompanyPublicKeyAllList"
	err := requests.New(pubkeyUrl).
		WithContext(context.Background()).
		WithMethod("GET").
		SetHeader("Authorization", "Bearer "+accessToken).
		Do().
		UnmarshalInto(&pubKeys)
	if err != nil {
		return "", err
	}
	for _, pub := range pubKeys {
		if pub.CompanyId == extra {
			pemString := "-----BEGIN PUBLIC KEY-----\n" + pub.CompanyRSAPubKey + "\n-----END PUBLIC KEY-----"
			return pemString, nil
		}
	}
	return "", errors.New("not found company public key")
}

/*
다음과 같은 구조를 가져오는 getUserProfile에서 받아온다.
GET 요청으로
https://devlogin.softcamp.co.kr/SCCloudOAuthService/3CJ55MSE-xLO7Sxt4-qUBKzbcs-XP2cgGEq/manage/getUserProfileSetInfo?companyId=3CJ55MSE-xLO7Sxt4-qUBKzbcs-XP2cgGEq&userId=admin@socam.info

{
    "companyId": "3CJ55MSE-xLO7Sxt4-qUBKzbcs-XP2cgGEq",
    "customProfileInfo": [
        {
            "key": "RequestPolicyUse",
            "value": "true",
            "desc": null,
            "uiType": null,
            "use": true,
            "additionalInformation": "true or false",
            "insertTimeDate": null,
            "updateTimeDate": null
        },
        {
            "key": "RequestPolicyAllowed",
            "value": "\"path:*\",\"method:*\"",
            "desc": null,
            "uiType": null,
            "use": true,
            "additionalInformation": "allowed list of path and method",
            "insertTimeDate": null,
            "updateTimeDate": null
        }
	]
}
*/

func getCustomProfileInfo(domain, extra, accessToken, userId string) (string, string, error) {
	type CustomProfileInfo struct {
		Key   string `json:"key"`
		Value string `json:"value"`
		Use   bool   `json:"use"`
	}

	type Security365CustomProfileInfo struct {
		CompanyId         string              `json:"companyId"`
		CustomProfileInfo []CustomProfileInfo `json:"customProfileInfo"`
	}

	var customProfileInfo Security365CustomProfileInfo
	customProfileInfoUrl := "https://" + domain + "/SCCloudOAuthService/" + extra + "/manage/getUserProfileSetInfo?companyId=" + extra + "&userId=" + userId
	err := requests.New(customProfileInfoUrl).
		WithContext(context.Background()).
		WithMethod("GET").
		SetHeader("Authorization", "Bearer "+accessToken).
		Do().
		UnmarshalInto(&customProfileInfo)
	if err != nil {
		return "", "", err
	}

	allowPolicy := ""
	denyPolicy := ""
	for _, info := range customProfileInfo.CustomProfileInfo {
		if info.Key == "RequestPolicyAllowed" && info.Use {
			allowPolicy = info.Value
		} else if info.Key == "RequestPolicyDenied" && info.Use {
			denyPolicy = info.Value
		}

	}
	return allowPolicy, denyPolicy, nil
}

func getCompanyRSAPubKey(domain, extra, accessToken string) (*rsa.PublicKey, error) {
	pubKey, err := getCompanyRSAPubKeyPemString(domain, extra, accessToken)
	if err != nil {
		return nil, err
	}
	pubKeyBytes := []byte(pubKey)
	pubKeyInterface, err := jwt.ParseRSAPublicKeyFromPEM(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return pubKeyInterface, nil
}

func getJWTDecodedPayload(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid token")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
