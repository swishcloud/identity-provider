package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"

	"github.com/swishcloud/gostudy/email"
	"github.com/swishcloud/goweb"
	"github.com/swishcloud/goweb/auth"
	"github.com/swishcloud/identity-provider/global"
	"github.com/swishcloud/identity-provider/storage"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

type Config struct {
	HYDRA_HOST               string       `yaml:"hydra_host"`
	HYDRA_PUBLIC_PORT        string       `yaml:"hydra_public_port"`
	HYDRA_ADMIN_PORT         string       `yaml:"hydra_admin_port"`
	IS_HTTPS                 bool         `yaml:"is_https"`
	LISTEN_ADDRESS           string       `yaml:"listen_address"`
	WEBSITE_NAME             string       `yaml:"website_name"`
	SECRET                   string       `yaml:"secret"`
	DB_CONN_INFO             string       `yaml:"db_conn_info"`
	Post_Logout_Redirect_Uri string       `yaml:"post_logout_redirect_uri"`
	Email                    Config_email `yaml:"email"`
}
type Config_email struct {
	Smtp_username string `yaml:"smtp_username"`
	Smtp_password string `yaml:"smtp_password"`
	Smtp_addr     string `yaml:"smtp_addr"`
}

type IDPServer struct {
	emailSender   email.EmailSender
	engine        *goweb.Engine
	config        *Config
	oauth2_config *oauth2.Config
}

func NewIDPServer(configPath string) *IDPServer {
	s := &IDPServer{}
	//read config
	s.config = &Config{}
	//s.config.Email = &Config_email{}
	b, err := ioutil.ReadFile(configPath)
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(b, s.config)
	if err != nil {
		panic(err)
	}
	s.engine = goweb.Default()
	s.engine.WM.HandlerWidget = &HandlerWidget{}
	s.emailSender = email.EmailSender{UserName: s.config.Email.Smtp_username, Password: s.config.Email.Smtp_password, Addr: s.config.Email.Smtp_addr, Name: s.config.WEBSITE_NAME}
	s.oauth2_config = &oauth2.Config{
		ClientID:     "IDENTITY_PROVIDER",
		ClientSecret: s.config.SECRET,
		Scopes:       []string{"offline", "openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_PUBLIC_PORT, s.config.IS_HTTPS, "/op/oauth2/auth", nil),
			TokenURL: global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_PUBLIC_PORT, s.config.IS_HTTPS, "/op/oauth2/token", nil),
		},
	}
	return s
}
func (server *IDPServer) GetStorage(ctx *goweb.Context) storage.Storage {
	m := ctx.Data["storage"]
	if m == nil {
		m = storage.NewSQLManager(server.config.DB_CONN_INFO)
		ctx.Data["storage"] = m
	}
	return m.(storage.Storage)
}

func (server *IDPServer) newPageModel(ctx *goweb.Context, data interface{}) pageModel {
	m := pageModel{}
	m.Data = data
	m.MobileCompatible = true
	u, _ := GetLoginUser(ctx)
	m.User = u
	m.WebsiteName = server.config.WEBSITE_NAME
	return m
}

func (s *IDPServer) Serve() {
	privileged_g := s.engine.Group()
	privileged_g.Use(introspectTokenMiddleware(s.config))
	privileged_g.GET("/", func(ctx *goweb.Context) {
		ctx.RenderPage(s.newPageModel(ctx, nil), "templates/layout.html", "templates/index.html")
	})
	s.engine.RegexMatch(regexp.MustCompile(`/static/.+`), func(context *goweb.Context) {
		http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))).ServeHTTP(context.Writer, context.Request)
	})
	s.engine.GET("/callback", func(ctx *goweb.Context) {
		fmt.Fprint(ctx.Writer, ctx.Request.RequestURI)
	})
	s.engine.GET("/consent", func(ctx *goweb.Context) {
		consent_challenge := ctx.Request.URL.Query().Get("consent_challenge")
		parameters := url.Values{}
		parameters.Add("consent_challenge", consent_challenge)
		b := global.SendRestApiRequest("GET", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, s.config.IS_HTTPS, ConsentPath, parameters), nil)
		res := HydraConsentRes{}
		json.Unmarshal(b, &res)

		user := s.GetStorage(ctx).GetUserById(res.Subject)

		body := HydraConsentAcceptBody{}
		body.Grant_access_token_audience = res.Requested_access_token_audience
		body.Grant_scope = res.Requested_scope
		body.Remember = true
		body.Remember_for = 60 * 30
		body.Session = HydraConsentAcceptBodySession{Id_token: map[string]interface{}{"name": user.Name, "avatar": user.Avatar, "email": user.Email}}
		b, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		putRes := global.SendRestApiRequest("PUT", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, s.config.IS_HTTPS, ConsentPath+"/accept", parameters), b)
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
		if !s.config.IS_HTTPS {
			redirectUrl.Scheme = "http"
		}
		http.Redirect(ctx.Writer, ctx.Request, redirectUrl.String(), 302)
	})
	s.engine.GET("/register", func(ctx *goweb.Context) {
		ctx.RenderPage(s.newPageModel(ctx, nil), "templates/layout.html", "templates/register.html")
	})
	s.engine.POST("/register", RegisterHandler(s))
	s.engine.GET(Path_Email_Validate, EmailValidateHandler(s))
	s.engine.GET(Path_Register_Succeeded, RegisterSucceededHandler(s))
	s.engine.GET("/login", func(ctx *goweb.Context) {
		login_challenge := ctx.Request.URL.Query().Get("login_challenge")
		if login_challenge == "" {
			//issue login request for the site itself
			url := s.oauth2_config.AuthCodeURL("state-string", oauth2.AccessTypeOffline)
			http.Redirect(ctx.Writer, ctx.Request, url, 302)
		} else {
			//processing login request from thid-party website or the site itself
			parameters := url.Values{}
			parameters.Add("login_challenge", login_challenge)

			b := global.SendRestApiRequest("GET", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, s.config.IS_HTTPS, LoginPath, parameters), nil)
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
				AcceptLogin(s.config, ctx, login_challenge, *(s.GetStorage(ctx).GetUserById(loginRes.Subject)))
			} else {
				ctx.RenderPage(s.newPageModel(ctx, nil), "templates/layout.html", "templates/login.html")
			}
		}
	})
	s.engine.POST("/login", LoginHandler(s))
	s.engine.GET("/login-callback", func(ctx *goweb.Context) {
		code := ctx.Request.URL.Query().Get("code")
		token, err := s.oauth2_config.Exchange(context.Background(), code)
		if err != nil {
			ctx.Writer.Write([]byte(err.Error()))
			return
		}
		auth.Login(ctx, token, global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_PUBLIC_PORT, s.config.IS_HTTPS, jwk_json_path, nil))
		client := s.oauth2_config.Client(context.Background(), token)
		token.SetAuthHeader(ctx.Request)
		resp, err := client.Get("http://" + s.config.LISTEN_ADDRESS + "/user_info")
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
	s.engine.GET("/logout", func(ctx *goweb.Context) {
		logout_challenge := ctx.Request.URL.Query().Get("logout_challenge")
		//logout requrest from third-party site
		parameters := url.Values{}
		parameters.Add("logout_challenge", logout_challenge)

		b := global.SendRestApiRequest("GET", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, s.config.IS_HTTPS, LogoutPath, parameters), nil)
		information := hydraLogoutRequestInformation{}
		err := json.Unmarshal(b, &information)
		if err != nil {
			panic(err)
		}
		putRes := global.SendRestApiRequest("PUT", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, s.config.IS_HTTPS, LogoutPath+"/accept", parameters), nil)
		logoutAcceptRes := HydraLogoutAcceptRes{}
		err = json.Unmarshal(putRes, &logoutAcceptRes)
		if err != nil {
			panic(err)
		}
		redirectUrl, err := url.ParseRequestURI(logoutAcceptRes.Redirect_to)
		if !s.config.IS_HTTPS {
			redirectUrl.Scheme = "http"
		}
		http.Redirect(ctx.Writer, ctx.Request, redirectUrl.String(), 302)
	})
	privileged_g.POST("/logout", func(ctx *goweb.Context) {
		//logout requrest from this site itself
		auth.Logout(ctx, func(id_token string) {
			parameters := url.Values{}
			parameters.Add("id_token_hint", id_token)
			redirect_url := s.config.Post_Logout_Redirect_Uri
			parameters.Add("post_logout_redirect_uri", redirect_url)
			http.Redirect(ctx.Writer, ctx.Request, global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_PUBLIC_PORT, s.config.IS_HTTPS, sessions_logout_path, parameters), 302)

		})
	})
	log.Println("accepting tcp connections on http://" + s.config.LISTEN_ADDRESS)
	server := http.Server{
		Addr:    s.config.LISTEN_ADDRESS,
		Handler: s.engine,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

type HandlerWidget struct {
}

func (*HandlerWidget) Pre_Process(ctx *goweb.Context) {
}
func (*HandlerWidget) Post_Process(ctx *goweb.Context) {
	m := ctx.Data["storage"]
	if m != nil {
		if ctx.Ok {
			m.(storage.Storage).Commit()
		} else {
			m.(storage.Storage).Rollback()
		}
	}
}
