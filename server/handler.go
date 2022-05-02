package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/swishcloud/gostudy/common"
	"github.com/swishcloud/gostudy/keygenerator"
	"github.com/swishcloud/identity-provider/global"
	"github.com/swishcloud/identity-provider/internal"
	"github.com/swishcloud/identity-provider/storage"
	"github.com/swishcloud/identity-provider/storage/models"

	"github.com/swishcloud/goweb"
	"github.com/swishcloud/goweb/auth"
)

const (
	Path_Login              = "/login"
	Path_Login_Acceptance   = "/login-acceptance"
	Path_Email_Validate     = "/email-validate"
	Path_Register_Succeeded = "/register-succeeded"
	Path_Change_Password    = "/change-password"
	Path_User_Info          = "/user_info"
	Path_Profile            = "/profile"
	Path_Password_Reset     = "/password_reset"
	Path_Logout             = "/logout"
)

func ApprovalNativeAppHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		ctx.RenderPage(s.newPageModel(ctx, ctx.Request.URL.Query().Get("code")), "templates/layout.html", "templates/approvalnativeapp.html")
	}
}
func ChangePasswordHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		if ctx.Request.Method == "GET" {
			email := ctx.Request.Form.Get("EMAIL")
			ctx.RenderPage(s.newPageModel(ctx, email), "templates/layout.html", "templates/change_password.html")
		} else {
			password := ctx.Request.PostForm.Get("password")
			confirmPassword := ctx.Request.PostForm.Get("confirmPassword")
			if password != confirmPassword {
				panic("password and confirm password are inconsistent")
			}
			if len(password) < 8 {
				panic("password length can't less than 8")
			}
			user, err := s.GetLoginUser(ctx)
			if err != nil {
				email := ctx.Request.Form.Get("EMAIL")
				for _, cookie := range ctx.Request.Cookies() {
					if cookie.Name == "vc" {
						if ok, err := check_verification_code(s.GetStorage(ctx), email, cookie.Value, internal.VC_LENGTH_PASSWORD_RESET); ok && err == nil {
							user = s.GetStorage(ctx).GetUserByEmail(email)
						}
						break
					}
				}
			}
			if user == nil {
				panic("login is invalid")
			}
			s.invalidateLoginSession(user.Id)
			s.invalidateConsentSession(user.Id, nil)
			s.GetStorage(ctx).ChangePassword(user.Id, password)
			ctx.Success(Path_Login)
		}
	}
}
func PasswordResetHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		if ctx.Request.Method == "GET" {
			email := ctx.Request.Form.Get("EMAIL")
			code := ctx.Request.Form.Get("CODE")
			if email != "" && code != "" {
				//third step, the reset password url is accessed
				user := s.GetStorage(ctx).GetUserByEmail(email)
				if user == nil {
					panic("the user does not exist")
				}
				var vc string
				for _, cookie := range ctx.Request.Cookies() {
					if cookie.Name == "vc" {
						vc = cookie.Value
						break
					}
				}
				if vc == "" {
					panic("the link is invalid")
				}
				code = vc + code
				if ok, err := check_verification_code(s.GetStorage(ctx), email, code, internal.VC_LENGTH_PASSWORD_RESET_FORM); !ok || err != nil {
					panic("the link is invalid")
				}
				//update code again
				verification_code, err := keygenerator.NewKey(internal.VC_LENGTH_PASSWORD_RESET, false, false, false, true)
				if err != nil {
					panic(err)
				}
				s.GetStorage(ctx).UpdateUserVerificationCode(user.Id, &verification_code)
				cookie := &http.Cookie{
					Name:  "vc",
					Value: verification_code,
				}
				http.SetCookie(ctx.Writer, cookie)
				ctx.RenderPage(s.newPageModel(ctx, email), "templates/layout.html", "templates/change_password.html")
			} else {
				//first step
				ctx.RenderPage(s.newPageModel(ctx, nil), "templates/layout.html", "templates/password_reset.html")
			}
		} else {
			//second step, send reset password url link
			email := ctx.Request.Form.Get("email")
			user := s.GetStorage(ctx).GetUserByEmail(email)
			if user == nil {
				panic("the user does not exist!")
			}
			if !user.Email_confirmed {
				panic("your email is registered but not confirmed yet, please check your email box")
			}
			verification_code, err := keygenerator.NewKey(internal.VC_LENGTH_PASSWORD_RESET_FORM, false, false, false, true)
			if err != nil {
				panic(err)
			}
			s.GetStorage(ctx).UpdateUserVerificationCode(user.Id, &verification_code)
			cookie := &http.Cookie{
				Name:  "vc",
				Value: verification_code[:10],
			}
			http.SetCookie(ctx.Writer, cookie)
			parameters := url.Values{}
			parameters.Add("EMAIL", email)
			parameters.Add("CODE", verification_code[10:50])
			reset_url := "https://" + s.config.Website_domain + Path_Password_Reset + "?" + parameters.Encode()
			s.emailSender.SendEmail(user.Email, "RESET PASSWORD", fmt.Sprintf("<html><body>"+
				"Hello %s，<br/><br/>"+
				"Please click the following url link to reset your password：<br/><br/>"+
				"<a href='%s'>%s</a><br/><br/>"+
				"If you failed to open the above link，please copy it and paste in browser to directly access, thanks!", user.Name, reset_url, reset_url)+
				"</body></html>", s.config.Email.Plain)
			ctx.Success(nil)
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
		user := s.GetStorage(ctx).GetUserByName(username)
		activateAddr := global.GetUriString(s.config.Website_domain, s.config.Website_port, Path_Email_Validate+"?email="+user.Email+"&code="+url.QueryEscape(*user.Email_activation_code), nil)
		if send_email != "0" {
			s.emailSender.SendEmail(user.Email, "邮箱激活", fmt.Sprintf("<html><body>"+
				"%s，您好:<br/><br/>"+
				"感谢您注册%s,您的登录邮箱为%s,请点击以下链接激活您的邮箱地址：<br/><br/>"+
				"<a href='%s'>%s</a><br/><br/>"+
				"如果以上链接无法访问，请将该网址复制并粘贴至浏览器窗口中直接访问。", user.Name, s.config.WEBSITE_NAME, user.Email, activateAddr, activateAddr)+
				"</body></html>", s.config.Email.Plain)
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
	max_password_failed_num := 5
	lock_timeout := 5
	user := s.GetUserByName(account)
	if user == nil {
		return nil, errors.New("not found the user.")
	}
	if user.Failure_num >= max_password_failed_num {
		if user.Lock_timestamp != nil {
			minutes := (int)(time.Now().UTC().Sub(*user.Lock_timestamp).Minutes())
			if minutes < lock_timeout {
				return nil, errors.New("your account has been locked due to too much login failure numbers,you could try again after " + strconv.Itoa(lock_timeout-minutes) + " minutes.")
			} else {
				s.ZeroLoginFailureNum(user.Id)
				user = s.GetUserByName(account)
			}
		} else {
			return nil, errors.New("this step could not have been reach if no exception,just double check why Lock_timestamp is NULL")
		}
	}
	if user == nil {
		return nil, errors.New("not found the user named " + account)
	}
	s.UpdateUserVerificationCode(user.Id, nil)
	if !user.Email_confirmed {
		return nil, errors.New("your email not confirmed yet")
	}
	if !common.Md5Check(user.Password, password) {
		s.IncreaseLoginFailureNum(user.Id)
		if user.Failure_num+1 >= max_password_failed_num {
			s.UpdateLockTimestamp(user.Id)
			return nil, errors.New("your account has been locked due to too much login failure numbers,you could try again after " + strconv.Itoa(lock_timeout) + " minutes.")
		} else {
			return nil, errors.New("password not match,you still have " + strconv.Itoa(max_password_failed_num-user.Failure_num-1) + " chances before getting locked")
		}
	}
	s.ZeroLoginFailureNum(user.Id)
	return user, nil
}
func LoginHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		login_challenge := ctx.Request.Form.Get("login_challenge")
		//login_challenge = login_challenge[1 : 1+32]
		account := ctx.Request.Form.Get("account")
		password := ctx.Request.Form.Get("password")
		key := ctx.Request.Form.Get("key")
		var user *models.User
		var err error
		if account != "" {
			user, err = loginAuthenticate(s.GetStorage(ctx), account, password)
			if err != nil {
				panic(err)
			}
		} else {
			if login_challenge := findLoginChallenge(login_challenge); login_challenge != nil && login_challenge.isAccepted && login_challenge.key == key {
				if ok, err := login_challenge.isValid(); !ok {
					panic(err)
				}
				user = login_challenge.user
			} else {
				panic("Login failed.")
			}
		}
		AcceptLogin(s, ctx, login_challenge, *user)
	}
}
func introspectToken(s *IDPServer, ctx *goweb.Context) (bool, *models.User, error) {
	token, err := auth.GetBearerToken(ctx)
	if err != nil {
		return false, nil, err
	}
	scope := ctx.Request.URL.Query().Get("scope")

	parameters := url.Values{}
	parameters.Add("token", token)
	parameters.Add("scope", scope)

	rar := common.NewRestApiRequest("POST", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, IntrospectPath, nil), []byte(parameters.Encode()))
	resp, err := s.rac.Do(rar)
	m, err := common.ReadAsMap(resp.Body)
	if err != nil {
		return false, nil, err
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
		return isActive, user, nil
	}
	return false, nil, nil
}
func IntrospectTokenHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		active, user, err := introspectToken(s, ctx)
		if err != nil {
			panic(err)
		}
		if active {
			ctx.Success(map[string]interface{}{"active": active, "sub": user.Id})
		} else {
			ctx.Success(map[string]interface{}{"active": active})
		}
	}
}
func userInfoHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		user := ctx.Data["user"].(*models.User)
		ctx.Success(user)
	}
}
func profileHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		user := ctx.Data["user"].(*models.User)
		_ = user
		ctx.RenderPage(s.newPageModel(ctx, ctx.Request.URL.Query().Get("code")), "templates/layout.html", "templates/profile.html")
	}
}
func loginAcceptanceHandler(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		user := ctx.Data["user"].(*models.User)
		challenge := ctx.Request.FormValue("challenge")
		login_challenge := findLoginChallenge(challenge)
		if login_challenge == nil {
			panic("the login challenge is not found")
		}
		if ok, err := login_challenge.isValid(); !ok {
			panic(err)
		}
		login_challenge.isAccepted = true
		login_challenge.user = user
		if key, err := keygenerator.NewKey(20, false, false, false, false); err != nil {
			panic(err)
		} else {
			login_challenge.key = key
		}
		s.wsHub.messages <- &WebSocketMessage{login_challenge.client, []byte(login_challenge.key)}
		ctx.Success(nil)
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
func apiMiddleware(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		active, user, err := introspectToken(s, ctx)
		if err != nil {
			panic(err)
		}
		if !active {
			panic("the token is not valid")
		}
		ctx.Data["user"] = user
	}
}

func introspectTokenMiddleware(s *IDPServer) goweb.HandlerFunc {
	return func(ctx *goweb.Context) {
		if s, err := auth.GetSessionByToken(s.rac, ctx, s.oauth2_config, s.config.Introspect_Token_Url, s.skip_tls_verify); err != nil {
			http.Redirect(ctx.Writer, ctx.Request, "/login", http.StatusFound)
		} else {
			u := &models.User{}
			u.Id = s.Claims["sub"].(string)
			u.Name = s.Claims["name"].(string)
			if avartar, ok := s.Claims["avatar"].(string); ok {
				u.Avatar = &avartar
			}
			ctx.Data["user"] = u
			ctx.Next()
		}
	}
}
func AcceptLogin(s *IDPServer, ctx *goweb.Context, login_challenge string, user models.User) {
	//get login request info
	parameters := url.Values{}
	parameters.Add("login_challenge", login_challenge)
	rar := common.NewRestApiRequest("GET", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, LoginPath, parameters), nil)
	resp, err := s.rac.Do(rar)
	if err != nil {
		panic(err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	loginRes := HydraLoginRes{}
	err = json.Unmarshal(b, &loginRes)
	if err != nil {
		panic(err)
	}
	log.Println(string(b))
	//check if the challenge has already expired
	if login_challenge := findLoginChallenge(login_challenge); login_challenge != nil {
		if ok, err := login_challenge.isValid(); !ok {
			panic(err)
		}
	} else {
		panic("not found chanllenge")
	}
	//invalidate previous tokens
	s.invalidateConsentSession(user.Id, &loginRes.Client.Client_id)
	//accept this login request
	body := HydraLoginAcceptBody{}
	body.Subject = user.Id
	body.Remember = false
	b, err = json.Marshal(body)
	if err != nil {
		panic(err)
	}
	parameters = url.Values{}
	parameters.Add("login_challenge", login_challenge)
	rar = common.NewRestApiRequest("PUT", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, LoginPath+"/accept", parameters), b)
	resp, err = s.rac.Do(rar)
	if err != nil {
		panic(err)
	}
	putRes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	loginAcceptRes := HydraLoginAcceptRes{}
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

func check_verification_code(storage storage.Storage, email string, verification_code string, length int) (bool, error) {
	user := storage.GetUserByEmail(email)
	if user == nil {
		return false, errors.New("the email does not exists")
	}
	storage.UpdateUserVerificationCode(user.Id, nil)
	if user.Verification_code == nil || user.Verification_code_update_timestamp == nil || *user.Verification_code != verification_code {
		return false, errors.New("the email or verification code is invalid")
	}
	if len(verification_code) != length {
		return false, errors.New("the verification code has expired")
	}
	diff := time.Now().UTC().Sub(*user.Verification_code_update_timestamp).Minutes()
	if diff > 5 {
		return false, errors.New("the verification code has expired")
	} else if diff < 0 {
		return false, errors.New("the verification code update timestamp is INVALID")
	}
	return true, nil
}
func (s *IDPServer) GetLoginUser(ctx *goweb.Context) (*models.User, error) {
	if s, err := auth.GetSessionByToken(s.rac, ctx, s.oauth2_config, s.config.Introspect_Token_Url, s.skip_tls_verify); err != nil {
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
	Skip            bool                 `json:"skip"`
	Subject         string               `json:"subject"`
	Client          HydraLoginRes_Client `json:"client"`
	Request_url     string               `json:"request_url"`
	Requested_scope []string             `json:"requested_scope"`
	Oidc_context    interface{}          `json:"oidc_context"`
	Created_at      string               `json:"created_at"`
	Updated_at      string               `json:"updated_at"`
	Context         interface{}          `json:"context"`
}
type HydraLoginRes_Client struct {
	Client_id string `json:"client_id"`
}
type HydraConsentSessionRes struct {
	Consent_request HydraConsentSessionRes_Consent_request `json:"consent_request"`
}
type HydraConsentSessionRes_Consent_request struct {
	Client HydraConsentSessionRes_Consent_request_client `json:"client"`
}
type HydraConsentSessionRes_Consent_request_client struct {
	Client_id string `json:"client_id"`
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
