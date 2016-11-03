package gosugar

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/mitchellh/mapstructure"
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
	Id                     string                     `mapstructure:"id"`
	SessionType            string                     `mapstructure:"type"`
	ShowWizard             string                     `mapstructure:"show_wizard"`
	FullName               string                     `mapstructure:"full_name"`
	Username               string                     `mapstructure:"user_name"`
	Roles                  []string                   `mapstructure:"roles"`
	IsPasswordExpired      bool                       `mapstructure:"is_password_expired"`
	PasswordExpiredMessage string                     `mapstructure:"password_expired_message"`
	Picture                string                     `mapstructure:"picture"`
	Hash                   string                     `mapstructure:"_hash"`
	ModuleList             []string                   `mapstructure:"module_list"`
	Address                SessionAddress             `mapstructure:",squash"`
	Organization           SessionOrganization        `mapstructure:",squash"`
	GlobalPreferences      SessionGlobalPreferences   `mapstructure:"preferences"`
	MyTeams                []SessionTeam              `mapstructure:"my_teams"`
	ACL                    map[string]SessionACLEntry `mapstructure:"acl"`
	UserPreferences        SessionUserPreferences
}
type SessionTeam struct {
	ID   string `mapstructure:"id"`
	Name string `mapstructure:"name"`
}
type SessionACLEntry struct {
	Fields     map[string]map[string]string `mapstructure:"fields"`
	Admin      string                       `mapstructure:"admin"`
	Developer  string                       `mapstructure:"developer"`
	Access     string                       `mapstructure:"access"`
	View       string                       `mapstructure:"view"`
	List       string                       `mapstructure:"list"`
	Edit       string                       `mapstructure:"edit"`
	Delete     string                       `mapstructure:"delete"`
	Import     string                       `mapstructure:"import"`
	Export     string                       `mapstructure:"export"`
	MassUpdate string                       `mapstructure:"massupdate"`
	Hash       string                       `mapstructure:"_hash"`
}
type SessionOrganization struct {
	IsManager         bool   `mapstructure:"is_manager"`
	IsTopLevelManager bool   `mapstructure:"is_top_level_manager"`
	ReportsToID       string `mapstructure:"reports_to_id"`
	ReportsToName     string `mapstructure:"reports_to_name"`
}
type SessionAddress struct {
	AddressStreet     string `mapstructure:"address_street"`
	AddressCity       string `mapstructure:"address_city"`
	AddressCountry    string `mapstructure:"address_country"`
	AddressPostalCode string `mapstructure:"address_postalcode"`
}
type SessionGlobalPreferences struct {
	Timezone                string              `mapstructure:"timezone"`
	TzOffsetDisplay         string              `mapstructure:"tz_offset"`
	TzOffsetSeconds         float64             `mapstructure:"tz_offset_sec"`
	DateFormat              string              `mapstructure:"datepref"`
	TimeFormat              string              `mapstructure:"timepref"`
	CurrencyID              int                 `mapstructure:"currency_id"`
	CurrencyName            string              `mapstructure:"currency_name"`
	CurrencySymbol          string              `mapstructure:"currency_symbol"`
	CurrencyISO             string              `mapstructure:"currency_iso"`
	CurrencyRate            float64             `mapstructure:"currency_rate"`
	ShowPreferredCurrency   bool                `mapstructure:"currency_show_preferred"`
	DecimalPrecision        int                 `mapstructure:"decimal_precision"`
	DecimalSeparator        string              `mapstructure:"decimal_separator"`
	NumberGroupingSeparator string              `mapstructure:"number_grouping_separator"`
	SignatureDefault        []string            `mapstructure:"signature_default"`
	SignaturePrepend        bool                `mapstructure:"signature_prepend"`
	EmailClientPreference   map[string]string   `mapstructure:"email_client_preference"`
	LocaleNameDefaultFormat string              `mapstructure:"default_locale_name_format"`
	FirstDayOfWeek          int                 `mapstructure:"first_day_of_week"`
	Sweetspot               string              `mapstructure:"preferences.sweetspot"`
	Language                string              `mapstructure:"preferences.language"`
	DefaultTeams            []map[string]string `mapstructure:"default_teams"`
}
type SessionUserPreferences struct {
	MailmergeOn                      string   `mapstructure:"mailmerge_on"`
	MaxTabs                          int      `mapstructure:"max_tabs"`
	SwapLastViewed                   string   `mapstructure:"swap_last_viewed"`
	SwapShortcuts                    string   `mapstructure:"swap_shortcuts"`
	SubpanelTabs                     string   `mapstructure:"subpanel_tabs"`
	UserTheme                        string   `mapstructure:"user_theme"`
	ModuleFavicon                    string   `mapstructure:"module_favicon"`
	HideTabs                         []string `mapstructure:"hide_tabs"`
	RemoveTabs                       []string `mapstructure:"remove_tabs"`
	NoOpps                           string   `mapstructure:"no_opps"`
	ReminderTime                     int      `mapstructure:"reminder_time"`
	Timezone                         string   `mapstructure:"timezone"`
	UT                               string   `mapstructure:"ut"`
	CurrencyID                       int      `mapstructure:"currency"`
	CurrencyDefaultSignificantDigits int      `mapstructure:"default_currency_significant_digits"`
	NumberGroupSeparator             string   `mapstructure:"num_grp_sep"`
	DecimalSeparator                 string   `mapstructure:"dec_sep"`
	DateFormat                       string   `mapstructure:"datef"`
	TimeFormat                       string   `mapstructure:"timef"`
	MailSMTPServer                   string   `mapstructure:"mail_smtpserver"`
	MailSMTPUser                     string   `mapstructure:"mail_smtpuser"`
	MailSMTPPass                     string   `mapstructure:"mail_smtppass"`
	LocaleDefaultNameFormat          string   `mapstructure:"default_locale_name_format"`
	ExportDelimeter                  string   `mapstructure:"export_delimeter"`
	ExportCharsetDefault             string   `mapstructure:"default_export_charset"`
	UseRealNames                     string   `mapstructure:"use_real_names"`
	MailSMTPAuthReq                  string   `mapstructure:"mail_smtpauth_req"`
	MailSMTPSSL                      bool     `mapstructure:"mail_smtpssl"`
	EmailLinkType                    string   `mapstructure:"email_link_type"`
	EmailShowCounts                  bool     `mapstructure:"email_show_counts"`
	CalendarPublishKey               string   `mapstructure:"calendar_publish_key"`
	LoginExpiration                  string   `mapstructure:"loginexpiration"`
	NavigationParadigm               string   `mapstructure:"navigation_paradigm"`
	EmailReminderTime                int      `mapstructure:"email_reminder_time"`
	CurrencyShowPreferred            bool     `mapstructure:"currency_show_preferred"`
	Fdow                             string   `mapstructure:"fdow"`
	SugarPDFMainFontName             string   `mapstructure:"sugarpdf_pdf_font_name_main"`
	SugarPDFMainFontSize             string   `mapstructure:"sugarpdf_pdf_font_size_main"`
	SugarPDFDataFontName             string   `mapstructure:"sugarpdf_pdf_font_name_data"`
	SugarPDFDataFontSize             string   `mapstructure:"sugarpdf_pdf_font_size_data"`
	Lockout                          string   `mapstructure:"lockout"`
	LoginFailed                      string   `mapstructure:"loginfailed"`
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

	var ok bool
	if resp, ok = resp["current_user"].(map[string]interface{}); ok {
		if err := mapstructure.WeakDecode(resp, &s.Info); err != nil {
			return err
		}
	} else {
		return errors.New("Couly not locate current_user json element.")
	}

	if err := s.CallJson("GET", "/me/preferences", nil, &resp); err != nil {
		return err
	}
	if err := mapstructure.WeakDecode(resp, &s.Info.UserPreferences); err != nil {
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
	var err error
	var b []byte
	if req == nil {
		b = nil
	} else {
		b, err = json.Marshal(req)
	}

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
