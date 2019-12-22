package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/swishcloud/identity-provider/global"
	"github.com/swishcloud/identity-provider/storage/models"

	"github.com/swishcloud/goweb"
	"github.com/swishcloud/goweb/auth"
)

const (
	LoginPath            = "/op/oauth2/auth/requests/login"
	ConsentPath          = "/op/oauth2/auth/requests/consent"
	LogoutPath           = "/op/oauth2/auth/requests/logout"
	SessionsPath         = "/op/oauth2/auth/sessions"
	IntrospectPath       = "/op/oauth2/introspect"
	jwk_json_path        = "/op/.well-known/jwks.json"
	sessions_logout_path = "/op/oauth2/sessions/logout"
)

func onError(ctx *goweb.Context, err error) {
	panic(err)
}
func introspectTokenMiddleware(config *Config) func(ctx *goweb.Context) {
	return func(ctx *goweb.Context) {
		if auth.HasLoggedIn(ctx) {
			ctx.Next()
			return
		}
		//if the user is not logged in the site,then check if has valid token
		if len(ctx.Request.Header["Authorization"]) == 0 {
			ctx.Writer.WriteHeader(http.StatusUnauthorized)
			panic(errors.New("the user is not logged in and no bearer auth token exists"))
		}
		bearerToken := ctx.Request.Header["Authorization"][0]
		tokenStrs := strings.Split(bearerToken, " ")
		if len(tokenStrs) != 2 {
			ctx.Writer.WriteHeader(http.StatusUnauthorized)
			panic(errors.New("token parameter format error"))
		}
		parameters := url.Values{}
		parameters.Add("token", tokenStrs[1])
		parameters.Add("scope", "profile")
		b := global.SendRestApiRequest("POST", global.GetUriString(config.HYDRA_HOST, config.HYDRA_ADMIN_PORT, config.IS_HTTPS, IntrospectPath, parameters), nil)
		m := map[string]interface{}{}
		err := json.Unmarshal(b, &m)
		if err != nil {
			panic(err)
		}
		isActive := m["active"].(bool)
		fmt.Println(m)
		if !isActive {
			ctx.Writer.WriteHeader(http.StatusUnauthorized)
			panic(errors.New("the token is not valid"))
		}
	}
}
func AcceptLogin(config *Config, ctx *goweb.Context, login_challenge string, user models.User) {
	body := HydraLoginAcceptBody{}
	body.Subject = user.Id
	body.Remember = true
	body.Remember_for = 60 * 5
	b, err := json.Marshal(body)
	parameters := url.Values{}
	parameters.Add("login_challenge", login_challenge)
	putRes := global.SendRestApiRequest("PUT", global.GetUriString(config.HYDRA_HOST, config.HYDRA_ADMIN_PORT, config.IS_HTTPS, LoginPath+"/accept", parameters), b)
	loginAcceptRes := HydraLoginAcceptRes{}
	fmt.Println(string(putRes))
	json.Unmarshal(putRes, &loginAcceptRes)
	redirectUrl, err := url.ParseRequestURI(loginAcceptRes.Redirect_to)
	if err != nil {
		panic(err)
	}
	if !config.IS_HTTPS {
		redirectUrl.Scheme = "http"
	}
	if ctx.Request.Method == "GET" {
		http.Redirect(ctx.Writer, ctx.Request, redirectUrl.String(), 302)
	} else {
		ctx.Success(redirectUrl.String())
	}
}

type pageModel struct {
	Data             interface{}
	MobileCompatible bool
	User             *models.User
	WebsiteName      string
	PageTitle        string
}

func GetLoginUser(ctx *goweb.Context) (*models.User, error) {
	if s, err := auth.GetSessionByToken(ctx); err != nil {
		return nil, err
	} else {
		u := &models.User{}
		u.Id = s.Claims["sub"].(string)
		u.Name = s.Claims["name"].(string)
		if avartar, ok := s.Claims["avatar"].(string); ok {
			u.Avatar = &avartar
		}
		return u, nil
	}
}

type LoginModel struct {
	AuthCodeUrl template.URL
}

type HydraLoginRes struct {
	Skip            bool        `json:"skip"`
	Subject         string      `json:"subject"`
	Client          interface{} `json:"client"`
	Request_url     string      `json:"request_url"`
	Requested_scope []string    `json:"requested_scope"`
	Oidc_context    interface{} `json:"oidc_context"`
	Context         interface{} `json:"context"`
}

type HydraLoginAcceptBody struct {
	Subject      string `json:"subject"`
	Remember     bool   `json:"remember"`
	Remember_for int    `json:"remember_for"`
	Acr          string `json:"acr"`
}
type HydraConsentRes struct {
	Skip                            bool        `json:"skip"`
	Subject                         string      `json:"subject"`
	Client                          interface{} `json:"client"`
	Request_url                     string      `json:"request_url"`
	Requested_scope                 []string    `json:"requested_scope"`
	Requested_access_token_audience []string    `json:"requested_access_token_audience"`
	Oidc_context                    interface{} `json:"oidc_context"`
	Context                         interface{} `json:"context"`
}
type HydraConsentAcceptBody struct {
	Grant_scope                 []string                      `json:"grant_scope"`
	Grant_access_token_audience []string                      `json:"grant_access_token_audience"`
	Remember                    bool                          `json:"remember"`
	Remember_for                int                           `json:"remember_for"`
	Session                     HydraConsentAcceptBodySession `json:"Session"`
}
type HydraConsentAcceptBodySession struct {
	Id_token map[string]interface{} `json:"id_token"`
}
type hydraLogoutRequestInformation struct {
	// The user for whom the logout was request.
	Subject string `json:"subject"`

	// The login session ID that was requested to log out.
	Sid string `json:"sid"`

	// The original request URL.
	Request_url string `json:"request_url"`

	// True if the request was initiated by a Relying Party (RP) / OAuth 2.0 Client. False otherwise.
	Rp_initiated bool `json:"rp_initiated"`
}
type HydraLoginAcceptRes struct {
	Redirect_to string `json:"redirect_to"`
}
type HydraConsentAcceptRes struct {
	Redirect_to string `json:"redirect_to"`
}
type HydraLogoutAcceptRes struct {
	Redirect_to string `json:"redirect_to"`
}
