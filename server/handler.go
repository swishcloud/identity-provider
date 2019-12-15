package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/swishcloud/gostudy/common"

	"github.com/swishcloud/identity-provider/global"
	"github.com/swishcloud/identity-provider/storage"
	"github.com/swishcloud/identity-provider/storage/models"
	"golang.org/x/oauth2"

	"github.com/swishcloud/goweb"
	"github.com/swishcloud/goweb/auth"
)

const (
	LoginPath            = "/oauth2/auth/requests/login"
	ConsentPath          = "/oauth2/auth/requests/consent"
	LogoutPath           = "/oauth2/auth/requests/logout"
	SessionsPath         = "/oauth2/auth/sessions"
	IntrospectPath       = "/oauth2/introspect"
	jwk_json_path        = "/.well-known/jwks.json"
	sessions_logout_path = "/oauth2/sessions/logout"
)

var store storage.Storage = storage.NewSQLManager()

func onError(ctx *goweb.Context, err error) {
	panic(err)
}
func Serve() {
	g := goweb.Default()
	privileged_g := g.Group()
	privileged_g.Use(introspectTokenMiddleware)
	privileged_g.GET("/", func(ctx *goweb.Context) {
		ctx.RenderPage(newPageModel(ctx, nil), "templates/layout.html", "templates/index.html")
	})
	g.RegexMatch(regexp.MustCompile(`/static/.+`), func(context *goweb.Context) {
		http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))).ServeHTTP(context.Writer, context.Request)
	})
	g.GET("/callback", func(ctx *goweb.Context) {
		fmt.Fprint(ctx.Writer, ctx.Request.RequestURI)
	})
	g.GET("/consent", func(ctx *goweb.Context) {
		consent_challenge := ctx.Request.URL.Query().Get("consent_challenge")
		parameters := url.Values{}
		parameters.Add("consent_challenge", consent_challenge)
		b := global.SendRestApiRequest("GET", global.GetUriString(global.Config.HYDRA_ADMIN_HOST, ConsentPath, parameters), nil)
		res := HydraConsentRes{}
		json.Unmarshal(b, &res)

		user := store.GetUserById(res.Subject)

		body := HydraConsentAcceptBody{}
		body.Grant_access_token_audience = res.Requested_access_token_audience
		body.Grant_scope = res.Requested_scope
		body.Remember = true
		body.Remember_for = 60 * 30
		body.Session = HydraConsentAcceptBodySession{Id_token: map[string]interface{}{"name": user.Name, "avatar": user.Avatar}}
		b, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		putRes := global.SendRestApiRequest("PUT", global.GetUriString(global.Config.HYDRA_ADMIN_HOST, ConsentPath+"/accept", parameters), b)
		consentAcceptRes := HydraConsentAcceptRes{}
		err = json.Unmarshal(putRes, &consentAcceptRes)
		if err != nil {
			panic(err)
		}
		redirectUrl, err := url.ParseRequestURI(consentAcceptRes.Redirect_to)
		fmt.Println("consent redirect:", consentAcceptRes.Redirect_to)
		if err != nil {
			panic(err)
		}
		if !global.Config.IS_HTTPS {
			redirectUrl.Scheme = "http"
		}
		http.Redirect(ctx.Writer, ctx.Request, redirectUrl.String(), 302)
	})
	var conf = &oauth2.Config{
		ClientID:     "IDENTITY_PROVIDER",
		ClientSecret: global.Config.SECRET,
		Scopes:       []string{"offline", "openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://" + global.Config.HYDRA_PUBLIC_HOST + "/oauth2/auth",
			TokenURL: "http://" + global.Config.HYDRA_PUBLIC_HOST + "/oauth2/token",
		},
	}
	g.GET("/register", func(ctx *goweb.Context) {
		ctx.RenderPage(newPageModel(ctx, nil), "templates/layout.html", "templates/register.html")
	})
	g.POST("/register", func(ctx *goweb.Context) {
		username := ctx.Request.PostForm.Get("username")
		password := ctx.Request.PostForm.Get("password")
		confirmPassword := ctx.Request.PostForm.Get("confirmPassword")
		email := ctx.Request.PostForm.Get("email")
		if password != confirmPassword {
			ctx.Failed("password and confirm password are inconsistent")
			return
		}
		store.AddUser(username, password, email)
		ctx.Success(struct {
			RedirectUri string `json:"redirectUri"`
		}{RedirectUri: "/login"})
	})
	g.GET("/login", func(ctx *goweb.Context) {
		login_challenge := ctx.Request.URL.Query().Get("login_challenge")
		if login_challenge == "" {
			//issue login request for the site itself
			url := conf.AuthCodeURL("state-string", oauth2.AccessTypeOffline)
			http.Redirect(ctx.Writer, ctx.Request, url, 302)
		} else {
			//processing login request from thid-party website or the site itself
			parameters := url.Values{}
			parameters.Add("login_challenge", login_challenge)

			b := global.SendRestApiRequest("GET", global.GetUriString(global.Config.HYDRA_ADMIN_HOST, LoginPath, parameters), nil)
			loginRes := HydraLoginRes{}
			err := json.Unmarshal(b, &loginRes)
			if err != nil {
				ctx.Writer.Write(b)
				return
			}
			if err != nil {
				panic(err)
			}
			if loginRes.Skip {
				AcceptLogin(ctx, login_challenge, *store.GetUserById(loginRes.Subject))
			} else {
				ctx.RenderPage(newPageModel(ctx, nil), "templates/layout.html", "templates/login.html")
			}
		}
	})
	g.POST("/login", func(ctx *goweb.Context) {
		account := ctx.Request.Form.Get("account")
		password := ctx.Request.Form.Get("password")
		user := store.GetUserByName(account)
		if user == nil {
			panic("not found the user named " + account)
		}
		//if user.Password == nil {
		//	panic("the user not set password")
		//}
		if !common.Md5Check(user.Password, password) {
			panic("password not match")
		}
		login_challenge := ctx.Request.URL.Query().Get("login_challenge")
		AcceptLogin(ctx, login_challenge, *user)
	})
	g.GET("/login-callback", func(ctx *goweb.Context) {
		code := ctx.Request.URL.Query().Get("code")
		token, err := conf.Exchange(context.Background(), code)
		if err != nil {
			ctx.Writer.Write([]byte(err.Error()))
			return
		}
		auth.Login(ctx, token, global.GetUriString(global.Config.HYDRA_PUBLIC_HOST, jwk_json_path, nil))
		client := conf.Client(context.Background(), token)
		token.SetAuthHeader(ctx.Request)
		resp, err := client.Get("http://" + global.Config.LISTEN_ADDRESS + "/user_info")
		if err != nil {
			panic(err)
		}
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		log.Println(string(b))
		http.Redirect(ctx.Writer, ctx.Request, "/", 302)
	})
	privileged_g.GET("/user_info", func(ctx *goweb.Context) {

	})
	g.GET("/logout", func(ctx *goweb.Context) {
		logout_challenge := ctx.Request.URL.Query().Get("logout_challenge")
		//logout requrest from third-party site
		parameters := url.Values{}
		parameters.Add("logout_challenge", logout_challenge)

		b := global.SendRestApiRequest("GET", global.GetUriString(global.Config.HYDRA_ADMIN_HOST, LogoutPath, parameters), nil)
		information := hydraLogoutRequestInformation{}
		err := json.Unmarshal(b, &information)
		if err != nil {
			panic(err)
		}
		putRes := global.SendRestApiRequest("PUT", global.GetUriString(global.Config.HYDRA_ADMIN_HOST, LogoutPath+"/accept", parameters), nil)
		logoutAcceptRes := HydraLogoutAcceptRes{}
		err = json.Unmarshal(putRes, &logoutAcceptRes)
		if err != nil {
			panic(err)
		}
		redirectUrl, err := url.ParseRequestURI(logoutAcceptRes.Redirect_to)
		if !global.Config.IS_HTTPS {
			redirectUrl.Scheme = "http"
		}
		http.Redirect(ctx.Writer, ctx.Request, redirectUrl.String(), 302)
	})
	privileged_g.POST("/logout", func(ctx *goweb.Context) {
		//logout requrest from this site itself
		auth.Logout(ctx, func(id_token string) {
			parameters := url.Values{}
			parameters.Add("id_token_hint", id_token)
			redirect_url := global.GetUriString(global.Config.LISTEN_ADDRESS, "/login", nil)
			parameters.Add("post_logout_redirect_uri", redirect_url)
			http.Redirect(ctx.Writer, ctx.Request, global.GetUriString(global.Config.HYDRA_PUBLIC_HOST, sessions_logout_path, parameters), 302)

		})
	})
	fmt.Println("accepting tcp connections on http://" + global.Config.LISTEN_ADDRESS)
	server := http.Server{
		Addr:    global.Config.LISTEN_ADDRESS,
		Handler: g,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func introspectTokenMiddleware(ctx *goweb.Context) {
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
	b := global.SendRestApiRequest("POST", global.GetUriString(global.Config.HYDRA_ADMIN_HOST, IntrospectPath, parameters), nil)
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
func AcceptLogin(ctx *goweb.Context, login_challenge string, user models.User) {
	body := HydraLoginAcceptBody{}
	body.Subject = user.Id
	body.Remember = true
	body.Remember_for = 60 * 5
	b, err := json.Marshal(body)
	parameters := url.Values{}
	parameters.Add("login_challenge", login_challenge)
	putRes := global.SendRestApiRequest("PUT", global.GetUriString(global.Config.HYDRA_ADMIN_HOST, LoginPath+"/accept", parameters), b)
	loginAcceptRes := HydraLoginAcceptRes{}
	fmt.Println(string(putRes))
	json.Unmarshal(putRes, &loginAcceptRes)
	redirectUrl, err := url.ParseRequestURI(loginAcceptRes.Redirect_to)
	if err != nil {
		panic(err)
	}
	if !global.Config.IS_HTTPS {
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
		u.Avatar = s.Claims["avatar"].(string)
		return u, nil
	}
}
func newPageModel(ctx *goweb.Context, data interface{}) pageModel {
	m := pageModel{}
	m.Data = data
	m.MobileCompatible = true
	u, _ := GetLoginUser(ctx)
	m.User = u
	m.WebsiteName = global.Config.WEBSITE_NAME
	return m
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
