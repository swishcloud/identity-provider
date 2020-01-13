package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/swishcloud/goblog/common"
	"github.com/swishcloud/identity-provider/global"
	"github.com/swishcloud/identity-provider/internal"
	"github.com/swishcloud/identity-provider/storage"
	"github.com/swishcloud/identity-provider/storage/models"

	"github.com/swishcloud/goweb"
	"github.com/swishcloud/goweb/auth"
)

const (
	Path_Login              = "/login"
	Path_Email_Validate     = "/email-validate"
	Path_Register_Succeeded = "/register-succeeded"
	Path_Change_Password    = "/change-password"
)

func ApprovalNativeAppHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		code := ctx.Request.URL.Query().Get("code")
		ctx.RenderPage(s.newPageModel(ctx, code), "templates/layout.html", "templates/approvalnativeapp.html")
	}
}
func ChangePasswordHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		if ctx.Request.Method == "GET" {
			ctx.RenderPage(s.newPageModel(ctx, nil), "templates/layout.html", "templates/change_password.html")
		} else {
			password := ctx.Request.PostForm.Get("password")
			confirmPassword := ctx.Request.PostForm.Get("confirmPassword")
			if password != confirmPassword {
				panic("password and confirm password are inconsistent")
			}
			if len(password) < 8 {
				panic("password length can't less than 8")
			}
			user, err := GetLoginUser(ctx)
			if err != nil {
				panic("login is invalid")
			}
			s.GetStorage(ctx).ChangePassword(user.Id, password)
			ctx.Success(Path_Login)
		}
	}
}
func EmailValidateHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		email := ctx.Request.URL.Query().Get("email")
		code := ctx.Request.URL.Query().Get("code")
		s.GetStorage(ctx).EmailValidate(email, code)
		http.Redirect(ctx.Writer, ctx.Request, "/", 302)
	}
}
func RegisterHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		username := ctx.Request.PostForm.Get("username")
		password := ctx.Request.PostForm.Get("password")
		confirmPassword := ctx.Request.PostForm.Get("confirmPassword")
		email := ctx.Request.PostForm.Get("email")
		send_email := ctx.Request.PostForm.Get("send_email")
		if password != confirmPassword {
			ctx.Failed("password and confirm password are inconsistent")
			return
		}
		s.GetStorage(ctx).AddUser(username, password, email)
		host, port, err := net.SplitHostPort(ctx.Request.Host)
		if err != nil {
			panic(err)
		}
		user := s.GetStorage(ctx).GetUserByName(username)
		activateAddr := global.GetUriString(host, port, Path_Email_Validate+"?email="+user.Email+"&code="+url.QueryEscape(*user.Email_activation_code), nil)
		if send_email != "0" {
			s.emailSender.SendEmail(user.Email, "邮箱激活", fmt.Sprintf("<html><body>"+
				"%s，您好:<br/><br/>"+
				"感谢您注册%s,您的登录邮箱为%s,请点击以下链接激活您的邮箱地址：<br/><br/>"+
				"<a href='%s'>%s</a><br/><br/>"+
				"如果以上链接无法访问，请将该网址复制并粘贴至浏览器窗口中直接访问。", user.Name, s.config.WEBSITE_NAME, user.Email, activateAddr, activateAddr)+
				"</body></html>")
		}
		ctx.Success(struct {
			RedirectUri string `json:"redirectUri"`
		}{RedirectUri: Path_Register_Succeeded})
	}
}
func RegisterSucceededHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		ctx.RenderPage(s.newPageModel(ctx, nil), "templates/layout.html", "templates/register_succeeded.html")
	}
}
func loginAuthenticate(s storage.Storage, account, password string) (*models.User, error) {
	user := s.GetUserByName(account)
	if user == nil {
		return nil, errors.New("not found the user named " + account)
	}
	if !user.Email_confirmed {
		return nil, errors.New("your email not confirmed yet")
	}
	if !common.Md5Check(user.Password, password) {
		return nil, errors.New("password not match")
	}
	return user, nil
}
func LoginHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		account := ctx.Request.Form.Get("account")
		password := ctx.Request.Form.Get("password")
		user, err := loginAuthenticate(s.GetStorage(ctx), account, password)
		if err != nil {
			panic(err)
		}
		login_challenge := ctx.Request.URL.Query().Get("login_challenge")
		AcceptLogin(s, ctx, login_challenge, *user)
	}
}

func IntrospectTokenHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		token, err := auth.GetBearerToken(ctx)
		if err != nil {
			ctx.Failed(err.Error())
			return
		}
		scope := ctx.Request.URL.Query().Get("scope")

		parameters := url.Values{}
		parameters.Add("token", token)
		parameters.Add("scope", scope)

		b := global.SendRestApiRequest("POST", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, IntrospectPath, nil), []byte(parameters.Encode()), s.skip_tls_verify)
		m := map[string]interface{}{}
		err = json.Unmarshal(b, &m)
		if err != nil {
			panic(err)
		}
		isActive := m["active"].(bool)
		if isActive {
			sub := m["sub"].(string)
			iat := m["iat"].(float64)
			iat_time := internal.TimestampToTime(iat)
			user := s.GetStorage(ctx).GetUserById(sub)
			if iat_time.Before(user.Token_valid_after) {
				isActive = false
			}
		}
		ctx.Success(isActive)
	}
}

const (
	LoginPath            = "/oauth2/auth/requests/login"
	ConsentPath          = "/oauth2/auth/requests/consent"
	LogoutPath           = "/oauth2/auth/requests/logout"
	SessionsPath         = "/oauth2/auth/sessions"
	IntrospectPath       = "/oauth2/introspect"
	jwk_json_path        = "/.well-known/jwks.json"
	sessions_logout_path = "/oauth2/sessions/logout"
)

func onError(ctx *goweb.Context, err error) {
	panic(err)
}

func introspectTokenMiddleware(s *IDPServer) goweb.HandlerFunc {
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
		b := global.SendRestApiRequest("POST", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, IntrospectPath, parameters), nil, s.skip_tls_verify)
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
func AcceptLogin(s *IDPServer, ctx *goweb.Context, login_challenge string, user models.User) {
	body := HydraLoginAcceptBody{}
	body.Subject = user.Id
	body.Remember = true
	body.Remember_for = 60 * 5
	b, err := json.Marshal(body)
	parameters := url.Values{}
	parameters.Add("login_challenge", login_challenge)
	putRes := global.SendRestApiRequest("PUT", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, LoginPath+"/accept", parameters), b, s.skip_tls_verify)
	loginAcceptRes := HydraLoginAcceptRes{}
	fmt.Println(string(putRes))
	json.Unmarshal(putRes, &loginAcceptRes)
	redirectUrl, err := url.ParseRequestURI(loginAcceptRes.Redirect_to)
	if err != nil {
		panic(err)
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
