/*
 * Copyright 2019 VMware, Inc.  All rights reserved.  Licensed under the Apache v2 License.
 */

package govcd

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vmware/go-vcloud-director/v2/types/v56"
	"github.com/vmware/go-vcloud-director/v2/util"
)

// VCDClientOption defines signature for customizing VCDClient using
// functional options pattern.
type VCDClientOption func(*VCDClient) error

type VCDClient struct {
	Client      Client  // Client for the underlying VCD instance
	sessionHREF url.URL // HREF for the session API
	QueryHREF   url.URL // HREF for the query API
}

type OauthResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IdToken      string `json:"id_token"`
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (vcdCli *VCDClient) vcdloginurl() error {
	if err := vcdCli.Client.validateAPIVersion(); err != nil {
		return fmt.Errorf("could not find valid version for login: %s", err)
	}

	// find login address matching the API version
	var neededVersion VersionInfo
	for _, versionInfo := range vcdCli.Client.supportedVersions.VersionInfos {
		if versionInfo.Version == vcdCli.Client.APIVersion {
			neededVersion = versionInfo
			break
		}
	}

	loginUrl, err := url.Parse(neededVersion.LoginUrl)
	if err != nil {
		return fmt.Errorf("couldn't find a LoginUrl for version %s", vcdCli.Client.APIVersion)
	}
	vcdCli.sessionHREF = *loginUrl
	return nil
}

// vcdCloudApiAuthorize performs the authorization to VCD using open API
func (vcdCli *VCDClient) vcdCloudApiAuthorize(user, pass, org string) (*http.Response, error) {

	util.Logger.Println("[TRACE] Connecting to VCD using cloudapi")
	// This call can only be used by tenants
	rawUrl := vcdCli.sessionHREF.Scheme + "://" + vcdCli.sessionHREF.Host + "/cloudapi/1.0.0/sessions"

	// If we are connecting as provider, we need to qualify the request.
	if strings.EqualFold(org, "system") {
		rawUrl += "/provider"
	}
	util.Logger.Printf("[TRACE] URL %s\n", rawUrl)
	loginUrl, err := url.Parse(rawUrl)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL %s", rawUrl)
	}
	vcdCli.sessionHREF = *loginUrl
	req := vcdCli.Client.NewRequest(map[string]string{}, http.MethodPost, *loginUrl, nil)
	// Set Basic Authentication Header
	req.SetBasicAuth(user+"@"+org, pass)
	// Add the Accept header. The version must be at least 33.0 for cloudapi to work
	req.Header.Add("Accept", "application/*;version=33.0")
	return vcdCli.Client.Http.Do(req)

}

// vcdAuthorize authorizes the client and returns a http response
func (vcdCli *VCDClient) vcdAuthorize(user, pass, org string) (*http.Response, error) {

	var missingItems []string
	if user == "" {
		missingItems = append(missingItems, "user")
	}
	if pass == "" {
		missingItems = append(missingItems, "password")
	}
	if org == "" {
		missingItems = append(missingItems, "org")
	}
	if len(missingItems) > 0 {
		return nil, fmt.Errorf("authorization is not possible because of these missing items: %v", missingItems)
	}
	// No point in checking for errors here
	req := vcdCli.Client.NewRequest(map[string]string{}, http.MethodPost, vcdCli.sessionHREF, nil)
	// Set Basic Authentication Header
	if vcdCli.Client.OauthUrl != "" {
		util.Logger.Printf("[OAUTH]: add oauth token %s", vcdCli.Client.OauthAccessToken)
		req.Header.Add("Bearer", vcdCli.Client.OauthAccessToken)
		// APIGW needs Authorization2 for this header
		req.Header.Add("Authorization2", "Basic "+basicAuth(user+"@"+org, pass))
	} else {
		req.SetBasicAuth(user+"@"+org, pass)
	}

	// Add the Accept header for vCA
	req.Header.Add("Accept", "application/*+xml;version="+vcdCli.Client.APIVersion)
	util.Logger.Printf("[OAUTH]: Sending auth request URL %s Headers: %+v", req.URL, req.Header)

	resp, err := vcdCli.Client.Http.Do(req)
	util.Logger.Printf("[OAUTH]: Got auth response: %+v err %v", resp, err)

	if err != nil {
		return nil, fmt.Errorf("Error in vcdAuthorize: %v", err)
	}
	// If the VCD has disabled the call to /api/sessions, the attempt will fail with error 401 (unauthorized)
	// https://docs.vmware.com/en/VMware-Cloud-Director/10.0/com.vmware.vcloud.install.doc/GUID-84390C8F-E8C5-4137-A1A5-53EC27FE0024.html
	// TODO: convert this method to main once we drop support for 9.7
	if resp.StatusCode == 401 {
		if vcdCli.Client.OauthUrl != "" {
			return nil, fmt.Errorf("Error in vcdAuthorize, vcdCloudApiAuthorize not supported for oauth: %v", err)
		}
		resp, err = vcdCli.vcdCloudApiAuthorize(user, pass, org)
		if err != nil {
			return nil, err
		}
		resp, err = checkRespWithErrType(types.BodyTypeJSON, resp, err, &types.Error{})
	} else {
		resp, err = checkResp(resp, err)
	}

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Store the authorization header

	if vcdCli.Client.OauthUrl != "" {
		vcdCli.Client.VCDAuthHeader = AuthorizationHeader
		vcdCli.Client.VCDToken = resp.Header.Get(AuthorizationHeader)
	} else {
		vcdCli.Client.VCDToken = resp.Header.Get(BearerTokenHeader)
		vcdCli.Client.VCDAuthHeader = BearerTokenHeader
	}
	vcdCli.Client.IsSysAdmin = strings.EqualFold(org, "system")

	// Get query href
	vcdCli.QueryHREF = vcdCli.Client.VCDHREF
	vcdCli.QueryHREF.Path += "/query"
	return resp, nil
}

func (vcdCli *VCDClient) oauthAuthorize() (*http.Response, error) {
	util.Logger.Printf("[OAUTH]: server %s", vcdCli.Client.OauthUrl)
	var missingItems []string
	if vcdCli.Client.OauthClientId == "" {
		missingItems = append(missingItems, "OauthClientId")
	}
	if vcdCli.Client.OauthClientSecret == "" {
		missingItems = append(missingItems, "OauthClientSecret")
	}
	if len(missingItems) > 0 {
		return nil, fmt.Errorf("oauth is not possible because of these missing items: %v", missingItems)
	}
	at := os.Getenv("OAUTH_ACCESS_TOKEN")
	if at != "" {
		util.Logger.Printf("[OAUTH] using test token from envvar %s", at)
		vcdCli.Client.OauthAccessToken = at
		vcdCli.Client.OauthAccessTokenExpires = 10000
		resp := http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader("")),
		}
		return &resp, nil
	}

	form := url.Values{
		"client_id":     {vcdCli.Client.OauthClientId},
		"client_secret": {vcdCli.Client.OauthClientSecret},
		"grant_type":    {"CERT"},
		"scope":         {"openid"},
	}
	util.Logger.Printf("[OAUTH] sending oauth req to %s", vcdCli.Client.OauthUrl)
	resp, err := vcdCli.Client.Http.PostForm(vcdCli.Client.OauthUrl, form)
	if err != nil {
		return nil, fmt.Errorf("Error in oauth client request do: %v", err)
	}
	defer resp.Body.Close()

	oauthR := OauthResponse{}
	err = json.NewDecoder(resp.Body).Decode(&oauthR)
	if err != nil {
		return nil, fmt.Errorf("Unable to unmarshal oauth response: %v", err)
	}
	vcdCli.Client.OauthAccessToken = oauthR.AccessToken
	vcdCli.Client.OauthAccessTokenExpires = oauthR.ExpiresIn
	util.Logger.Printf("[OAUTH] got response %+v", oauthR)
	return resp, nil
}

// NewVCDClient initializes VMware vCloud Director client with reasonable defaults.
// It accepts functions of type VCDClientOption for adjusting defaults.
func NewVCDClient(vcdEndpoint url.URL, insecure bool, options ...VCDClientOption) *VCDClient {
	// Setting defaults

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 120 * time.Second, // Default timeout for TSL hand shake
	}

	vcdClient := &VCDClient{
		Client: Client{
			APIVersion: "32.0", // supported by 9.7+
			// UserAgent cannot embed exact version by default because this is source code and is supposed to be used by programs,
			// but any client can customize or disable it at all using WithHttpUserAgent() configuration options function.
			UserAgent: "go-vcloud-director",
			VCDHREF:   vcdEndpoint,
			Http: http.Client{
				Transport: transport,
				Timeout:   600 * time.Second, // Default value for http request+response timeout
			},
			MaxRetryTimeout: 60, // Default timeout in seconds for retries calls in functions
		},
	}

	// Override defaults with functional options
	for _, option := range options {
		err := option(vcdClient)
		if err != nil {
			// We do not have error in return of this function signature.
			// To avoid breaking API the only thing we can do is panic.
			panic(fmt.Sprintf("unable to initialize vCD client: %s", err))
		}
	}

	// optionally load certs.  Might be better to do this upfront rather than replace the transport, but do
	// not want to change the order at which the options are read in
	disableCompression := vcdClient.Client.OauthUrl != ""
	if vcdClient.Client.ClientTlsCert != "" {
		util.Logger.Printf("[OAUTH] setting up TLS certs")
		x509cert, err := tls.X509KeyPair([]byte(vcdClient.Client.ClientTlsCert), []byte(vcdClient.Client.ClientTlsKey))
		if err != nil {
			panic(fmt.Errorf("Unable to load key pair: %v", err))
		}
		certs := []tls.Certificate{x509cert}
		transport.TLSClientConfig = &tls.Config{Certificates: certs, InsecureSkipVerify: insecure}
		transport.DisableCompression = disableCompression
	}

	return vcdClient
}

// Authenticate is a helper function that performs a login in vCloud Director.
func (vcdCli *VCDClient) Authenticate(username, password, org string) error {
	_, err := vcdCli.GetAuthResponse(username, password, org)
	return err
}

// GetOauthResponse connects to the oath server to get a token
func (vcdCli *VCDClient) GetOauthResponse(username, password, org string) (*http.Response, error) {

	util.Logger.Println("[OAUTH] GetOauthResponse", "OauthUrl", vcdCli.Client.OauthUrl)
	if vcdCli.Client.OauthUrl != "" {
		resp, err := vcdCli.oauthAuthorize()
		if err != nil {
			return nil, fmt.Errorf("error oauth authorizing: %s", err)
		}
		util.Logger.Printf("oauthAuthorize response: %+v", resp)
		return resp, nil
	} else {
		return nil, fmt.Errorf("Oauth specified but no OauthUrl in client")
	}
}

// GetAuthResponse performs authentication and returns the full HTTP response
// The purpose of this function is to preserve information that is useful
// for token-based authentication
func (vcdCli *VCDClient) GetAuthResponse(username, password, org string) (*http.Response, error) {

	util.Logger.Println("[TRACE] GetAuthResponse", "OauthUrl", vcdCli.Client.OauthUrl)
	err := vcdCli.vcdloginurl()
	if err != nil {
		return nil, fmt.Errorf("error finding LoginUrl: %s", err)
	}

	// Choose correct auth mechanism based on what type of authentication is used. The end result
	// for each of the below functions is to set authorization token vcdCli.Client.VCDToken.
	var resp *http.Response
	switch {
	case vcdCli.Client.UseSamlAdfs:
		err = vcdCli.authorizeSamlAdfs(username, password, org, vcdCli.Client.CustomAdfsRptId)
		if err != nil {
			return nil, fmt.Errorf("error authorizing SAML: %s", err)
		}
	default:
		// Authorize
		resp, err = vcdCli.vcdAuthorize(username, password, org)
		if err != nil {
			return nil, fmt.Errorf("error authorizing: %s", err)
		}

	}

	return resp, nil
}

// SetToken will set the authorization token in the client, without using other credentials
// Up to version 29, token authorization uses the the header key x-vcloud-authorization
// In version 30+ it also uses X-Vmware-Vcloud-Access-Token:TOKEN coupled with
// X-Vmware-Vcloud-Token-Type:"bearer"
func (vcdCli *VCDClient) SetToken(org, authHeader, token string) error {
	vcdCli.Client.VCDAuthHeader = authHeader
	vcdCli.Client.VCDToken = token

	err := vcdCli.vcdloginurl()
	if err != nil {
		return fmt.Errorf("error finding LoginUrl: %s", err)
	}

	vcdCli.Client.IsSysAdmin = strings.EqualFold(org, "system")
	// Get query href
	vcdCli.QueryHREF = vcdCli.Client.VCDHREF
	vcdCli.QueryHREF.Path += "/query"

	// The client is now ready to connect using the token, but has not communicated with the vCD yet.
	// To make sure that it is working, we run a request for the org list.
	// This list should work always: when run as system administrator, it retrieves all organizations.
	// When run as org user, it only returns the organization the user is authorized to.
	// In both cases, we discard the list, as we only use it to certify that the token works.
	orgListHREF := vcdCli.Client.VCDHREF
	orgListHREF.Path += "/org"

	orgList := new(types.OrgList)

	_, err = vcdCli.Client.ExecuteRequest(orgListHREF.String(), http.MethodGet,
		"", "error connecting to vCD using token: %s", nil, orgList)
	if err != nil {
		return err
	}
	return nil
}

// Disconnect performs a disconnection from the vCloud Director API endpoint.
func (vcdCli *VCDClient) Disconnect() error {
	if vcdCli.Client.VCDToken == "" && vcdCli.Client.VCDAuthHeader == "" {
		return fmt.Errorf("cannot disconnect, client is not authenticated")
	}
	req := vcdCli.Client.NewRequest(map[string]string{}, http.MethodDelete, vcdCli.sessionHREF, nil)
	// Add the Accept header for vCA
	req.Header.Add("Accept", "application/xml;version="+vcdCli.Client.APIVersion)
	// Set Authorization Header
	req.Header.Add(vcdCli.Client.VCDAuthHeader, vcdCli.Client.VCDToken)
	if _, err := checkResp(vcdCli.Client.Http.Do(req)); err != nil {
		return fmt.Errorf("error processing session delete for vCloud Director: %s", err)
	}
	return nil
}

// WithMaxRetryTimeout allows default vCDClient MaxRetryTimeout value override
func WithMaxRetryTimeout(timeoutSeconds int) VCDClientOption {
	return func(vcdClient *VCDClient) error {
		vcdClient.Client.MaxRetryTimeout = timeoutSeconds
		return nil
	}
}

// WithAPIVersion allows to override default API version. Please be cautious
// about changing the version as the default specified is the most tested.
func WithAPIVersion(version string) VCDClientOption {
	return func(vcdClient *VCDClient) error {
		vcdClient.Client.APIVersion = version
		return nil
	}
}

// WithHttpTimeout allows to override default http timeout
func WithHttpTimeout(timeout int64) VCDClientOption {
	return func(vcdClient *VCDClient) error {
		vcdClient.Client.Http.Timeout = time.Duration(timeout) * time.Second
		return nil
	}
}

// WithSamlAdfs specifies if SAML auth is used for authenticating to vCD instead of local login.
// The following conditions must be met so that SAML authentication works:
// * SAML IdP (Identity Provider) is Active Directory Federation Service (ADFS)
// * WS-Trust authentication endpoint "/adfs/services/trust/13/usernamemixed" must be enabled on
// ADFS server
// By default vCD SAML Entity ID will be used as Relaying Party Trust Identifier unless
// customAdfsRptId is specified
func WithSamlAdfs(useSaml bool, customAdfsRptId string) VCDClientOption {
	return func(vcdClient *VCDClient) error {
		vcdClient.Client.UseSamlAdfs = useSaml
		vcdClient.Client.CustomAdfsRptId = customAdfsRptId
		return nil
	}
}

// WithHttpUserAgent allows to specify HTTP user-agent which can be useful for statistics tracking.
// By default User-Agent is set to "go-vcloud-director". It can be unset by supplying empty value.
func WithHttpUserAgent(userAgent string) VCDClientOption {
	return func(vcdClient *VCDClient) error {
		vcdClient.Client.UserAgent = userAgent
		return nil
	}
}

func WithOauthUrl(oauthUrl string) VCDClientOption {
	return func(vcdClient *VCDClient) error {
		vcdClient.Client.OauthUrl = oauthUrl
		return nil
	}
}

func WithOauthCreds(clientId, secret string) VCDClientOption {
	return func(vcdClient *VCDClient) error {
		vcdClient.Client.OauthClientId = clientId
		vcdClient.Client.OauthClientSecret = secret
		return nil
	}
}

func WithClientTlsCerts(cert, key string) VCDClientOption {
	return func(vcdClient *VCDClient) error {
		vcdClient.Client.ClientTlsCert = cert
		vcdClient.Client.ClientTlsKey = key
		return nil
	}
}
