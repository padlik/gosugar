package gosugar

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/goinggo/mapstructure"
	"io/ioutil"
	"net/http"
)

//Sugar authentication structure for oauth2 keys
type AuthRequest struct {
	GrantType    string `json:"grant_type"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	UserName     string `json:"username"`
	Password     string `json:"password"`
	Platform     string `json:"platform"`
}

type RefreshRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

//Sugar authentication response
type AuthResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int32  `json:"expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int32  `json:"refresh_expires_in"`
	DownloadToken    string `json:"download_token"`
}

type SessionInfo struct {
	Id         string   `jpath:"current_user.id"`
	ModuleList []string `jpath:"current_user.module_list"`
}

const service = "/rest/v10"

type Session struct {
	//Oauth2 access token
	AccessToken  string
	RefreshToken string

	//Url points to sugarcrm url, that should contain
	//protocol, but not service line, as REST v10 will be
	//used by default
	//Example: https://sugarinternal.sugarondemand.com
	//Note, that certificate checks are to be ignored.
	Url string

	//List of available modules
	Info SessionInfo
}

//Connect session to Sugar REST API
func (s *Session) Connect(username string, password string) error {
	auth := AuthRequest{"password", "sugar", "", username, password, "base"}
	var res AuthResponse

	//we do not expect partial response so ignoring offset parameter
	err := s.CallJson("POST", "/oauth2/token", &auth, &res)
	if err != nil {
		return err
	}

	s.AccessToken = res.AccessToken
	s.RefreshToken = res.RefreshToken
	if err = s.loadInfo(); err != nil {
		return err
	}
	return nil
}

//Session information
func (s *Session) loadInfo() error {

	var resp map[string]interface{}
	if err := s.CallJson("GET", "/me", nil, &resp); err != nil {
		return err
	}

	if err := mapstructure.DecodePath(resp, &s.Info); err != nil {
		return err
	}

    //for some reason Users module is not in module list
    //however it is available from Sugar
	if !s.sanityModule("Users") {
		s.Info.ModuleList = append(s.Info.ModuleList, "Users")
	}
	return nil
}

//Refresh token when expires (seems never needed)
func (s *Session) Refresh() error {
	if s.RefreshToken == "" {
		return errors.New("No refresh token available")
	}

	ref := RefreshRequest{"refresh_token", s.RefreshToken, "sugar", ""}
	var res AuthResponse
	err := s.CallJson("POST", " /oauth2/token", &ref, &res)
	if err != nil {
		s.RefreshToken = ""
		s.AccessToken = ""
		return err
	}

	s.AccessToken = res.AccessToken
	s.RefreshToken = res.RefreshToken
	if err = s.loadInfo(); err != nil {
		return err
	}
	return nil
}

//Make rest call and return response into rest pointer
//method - standard HTTP method (e.g. GET, POST)
//srv - REST service string e.g. "/me"
//req - data to marchall as JSON with the request
//resp - pointer to response
func (s *Session) CallJson(method string, srv string, req interface{}, resp interface{}) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}

	url := s.Url + service + srv
	rq, err := http.NewRequest(method, url, bytes.NewBuffer(b))
	rq.Header.Set("Content-Type", "application/json")
	if s.AccessToken != "" {
		rq.Header.Set("oauth-token", s.AccessToken)
	}

	//we need to eliminate SSL checks
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	rp, err := client.Do(rq)
	if err != nil {
		return err
	}
	defer rp.Body.Close()

	if rp.StatusCode == 401 {
		//trying to refresh token
		if err := s.Refresh(); err != nil {
			return errors.New("non OK response: " + rp.Status)
		}
	}

	if rp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(rp.Body)
		return errors.New("non OK response: " + rp.Status + "\nBody: " + string(body))
	}

	body, _ := ioutil.ReadAll(rp.Body)
	if err := json.Unmarshal(body, resp); err != nil {
		return err
	}

	return nil
}

func (s *Session) sanityModule(m string) bool {
	for _, v := range s.Info.ModuleList {
		if v == m {
			return true
		}
	}
	return false
}

func (s *Session) RunQuery(q *Query) (interface{}, error) {
	if ok := s.sanityModule(q.Module); !ok {
		return nil, fmt.Errorf("Module %v is not available for quering", q.Module)
	}

	var resp interface{}
	srv := "/" + q.Module + "/filter"
	if err := s.CallJson(q.Method, srv, q, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

//Make a new session
func NewSession(urlStr string) (*Session, error) {
	s := Session{Url: urlStr}
	return &s, nil
}
