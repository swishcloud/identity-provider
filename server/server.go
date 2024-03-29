package server

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/gorilla/websocket"
	"github.com/swishcloud/gostudy/common"
	"github.com/swishcloud/gostudy/email"
	"github.com/swishcloud/gostudy/keygenerator"
	"github.com/swishcloud/goweb"
	"github.com/swishcloud/goweb/auth"
	"github.com/swishcloud/identity-provider/global"
	"github.com/swishcloud/identity-provider/internal"
	"github.com/swishcloud/identity-provider/storage"
	"github.com/swishcloud/identity-provider/storage/models"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

const session_user_key = "session_user"

type Config struct {
	HYDRA_HOST               string       `yaml:"hydra_host"`
	HYDRA_PUBLIC_PORT        string       `yaml:"hydra_public_port"`
	HYDRA_ADMIN_PORT         string       `yaml:"hydra_admin_port"`
	LISTEN_ADDRESS           string       `yaml:"listen_address"`
	WEBSITE_NAME             string       `yaml:"website_name"`
	SECRET                   string       `yaml:"secret"`
	DB_CONN_INFO             string       `yaml:"db_conn_info"`
	Post_Logout_Redirect_Uri string       `yaml:"post_logout_redirect_uri"`
	Introspect_Token_Url     string       `yaml:"introspect_token_url"`
	Email                    Config_email `yaml:"email"`
	Tls_cert_file            string       `yaml:"tls_cert_file"`
	Tls_key_file             string       `yaml:"tls_key_file"`
	Website_domain           string       `yaml:"website_domain"`
	Website_port             string       `yaml:"website_port"`
}
type Config_email struct {
	Smtp_username string `yaml:"smtp_username"`
	Smtp_password string `yaml:"smtp_password"`
	Smtp_addr     string `yaml:"smtp_addr"`
	Plain         bool   `yaml:"plain"`
}

type IDPServer struct {
	emailSender     email.EmailSender
	engine          *goweb.Engine
	config          *Config
	oauth2_config   *oauth2.Config
	httpClient      *http.Client
	rac             *common.RestApiClient
	skip_tls_verify bool
	wsHub           *WebSocketHub
}

func NewIDPServer(configPath string, skip_tls_verify bool) *IDPServer {
	s := &IDPServer{}
	s.wsHub = newWebSocketHub()
	go s.wsHub.run()
	s.skip_tls_verify = skip_tls_verify
	s.httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: skip_tls_verify}}}
	http.DefaultClient = s.httpClient
	s.rac = common.NewRestApiClient(skip_tls_verify)
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
	s.engine.WM.HandlerWidget = &HandlerWidget{s: s}
	s.emailSender = email.EmailSender{UserName: s.config.Email.Smtp_username, Password: s.config.Email.Smtp_password, Addr: s.config.Email.Smtp_addr, Name: s.config.WEBSITE_NAME}
	s.oauth2_config = &oauth2.Config{
		ClientID:     "IDENTITY_PROVIDER",
		ClientSecret: s.config.SECRET,
		Scopes:       []string{"offline", "openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_PUBLIC_PORT, "/oauth2/auth", nil),
			TokenURL: global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_PUBLIC_PORT, "/oauth2/token", nil),
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
	u, _ := server.GetLoginUser(ctx)
	m.User = u
	m.WebsiteName = server.config.WEBSITE_NAME
	return m
}

const (
	Api_Path_Introspect_Token = "/api/introspect-token"
)

func (s *IDPServer) invalidateLoginSession(sub string) {
	rar := common.NewRestApiRequest("DELETE", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, SessionsPath+"/login?subject="+sub, nil), nil)
	resp, err := s.rac.Do(rar)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != 204 {
		panic("response status of deleting login sessions request:" + resp.Status)
	}
}
func (s *IDPServer) getConsentSessions(sub string, client *string) []HydraConsentSessionRes {
	parameters := url.Values{}
	parameters.Add("subject", sub)
	rar := common.NewRestApiRequest("GET", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, SessionsPath+"/consent", parameters), nil)
	resp, err := s.rac.Do(rar)
	if err != nil {
		panic(err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	res := []HydraConsentSessionRes{}
	json.Unmarshal(b, &res)
	if err != nil {
		panic(err)
	}
	if client != nil {
		for i := 0; i < len(res); i++ {
			if res[i].Consent_request.Client.Client_id != *client {
				res = append(res[:i], res[i+1:]...)
				i--
			}
		}
	}
	return res
}
func (s *IDPServer) invalidateConsentSession(sub string, client *string) {
	ss := s.getConsentSessions(sub, client)
	if len(ss) == 0 {
		log.Printf("No consent session need to be invalidated.")
		return
	}

	parameters := url.Values{}
	parameters.Add("subject", sub)
	if client != nil {
		parameters.Add("client", *client)
		parameters.Add("all", "false")
	} else {
		parameters.Add("all", "true")
	}
	rar := common.NewRestApiRequest("DELETE", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, SessionsPath+"/consent", parameters), nil)
	resp, err := s.rac.Do(rar)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != 204 {
		b, err := ioutil.ReadAll(resp.Body)
		res := HydraConsentRes{}
		json.Unmarshal(b, &res)
		if err != nil {
			panic(err)
		}
		panic("response status of deleting consent sessions request:" + resp.Status + "\r\n" + string(b))
	}
}

func (s *IDPServer) Serve() {
	BindAdminHandler(s)
	api_group := s.engine.Group()
	api_group.Use(apiMiddleware(s))
	api_group.GET(Path_User_Info, userInfoHandler(s))
	api_group.POST(Path_Login_Acceptance, loginAcceptanceHandler(s))
	privileged_g := s.engine.Group()
	privileged_g.Use(introspectTokenMiddleware(s))
	privileged_g.GET("/", func(ctx *goweb.Context) {
		ctx.RenderPage(s.newPageModel(ctx, nil), "templates/layout.html", "templates/index.html")
	})
	privileged_g.GET(Path_Profile, profileHandler(s))
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
		rar := common.NewRestApiRequest("GET", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, ConsentPath, parameters), nil)
		resp, err := s.rac.Do(rar)
		if err != nil {
			panic(err)
		}
		b, err := ioutil.ReadAll(resp.Body)
		res := HydraConsentRes{}
		json.Unmarshal(b, &res)

		user := s.GetStorage(ctx).GetUserById(res.Subject)

		body := HydraConsentAcceptBody{}
		body.Grant_access_token_audience = res.Requested_access_token_audience
		body.Grant_scope = res.Requested_scope
		body.Remember = false
		body.Session = HydraConsentAcceptBodySession{Id_token: map[string]interface{}{"name": user.Name, "avatar": user.Avatar, "email": user.Email}}
		b, err = json.Marshal(body)
		if err != nil {
			panic(err)
		}
		rar = common.NewRestApiRequest("PUT", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, ConsentPath+"/accept", parameters), b)
		resp, err = s.rac.Do(rar)
		if err != nil {
			panic(err)
		}
		putRes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		consentAcceptRes := HydraConsentAcceptRes{}
		err = json.Unmarshal(putRes, &consentAcceptRes)
		if err != nil {
			panic(err)
		}
		fmt.Println("consent redirect:", consentAcceptRes.Redirect_to)
		if err != nil {
			panic(err)
		}
		http.Redirect(ctx.Writer, ctx.Request, consentAcceptRes.Redirect_to, 302)
	})
	s.engine.GET("/register", func(ctx *goweb.Context) {
		ctx.RenderPage(s.newPageModel(ctx, nil), "templates/layout.html", "templates/register.html")
	})
	s.engine.POST("/register", RegisterHandler(s))
	s.engine.GET(Path_Password_Reset, PasswordResetHandler(s))
	s.engine.POST(Path_Password_Reset, PasswordResetHandler(s))
	s.engine.GET("/.approvalnativeapp", ApprovalNativeAppHandler(s))
	s.engine.GET(Path_Email_Validate, EmailValidateHandler(s))
	s.engine.GET(Path_Register_Succeeded, RegisterSucceededHandler(s))
	s.engine.GET(Path_Change_Password, ChangePasswordHandler(s))
	s.engine.POST(Path_Change_Password, ChangePasswordHandler(s))
	s.engine.GET("/ws", func(ctx *goweb.Context) {
		serveWs(s.wsHub, ctx.Writer.ResponseWriter, ctx.Request)
	})
	s.engine.GET("/login", func(ctx *goweb.Context) {
		login_challenge := ctx.Request.URL.Query().Get("login_challenge")
		if login_challenge == "" {
			//issue login request for the site itself
			url, err := auth.AuthCodeURL(ctx, s.oauth2_config)
			if err != nil {
				panic(err)
			}
			http.Redirect(ctx.Writer, ctx.Request, url, 302)
		} else {
			//processing login request from thid-party website or the site itself
			registerLoginChallenge(login_challenge)
			challenge := findLoginChallenge(login_challenge)
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
			if loginRes.Skip {
				AcceptLogin(s, ctx, login_challenge, *(s.GetStorage(ctx).GetUserById(loginRes.Subject)))
			} else {
				scan_login := true
				if loginRes.Client.Client_id == "FILESYNC_MOBILE" {
					scan_login = false
				}
				scan_login = false
				type Data struct {
					Login_challenge string
					Qrcode          string
				}
				d := Data{Login_challenge: login_challenge, Qrcode: challenge.qrcode}
				if scan_login {
					ctx.RenderPage(s.newPageModel(ctx, d), "templates/layout.html", "templates/scan-login.html")
				} else {
					ctx.RenderPage(s.newPageModel(ctx, d), "templates/layout.html", "templates/login.html")
				}
			}
		}
	})
	s.engine.GET("/qr_code", func(ctx *goweb.Context) {
		str := ctx.Request.FormValue("str")
		qrCode, _ := qr.Encode(str, qr.L, qr.Auto)
		qrCode, _ = barcode.Scale(qrCode, 300, 300)
		png.Encode(ctx.Writer, qrCode)
	})
	s.engine.POST("/login", LoginHandler(s))
	s.engine.GET("/login-callback", func(ctx *goweb.Context) {
		token, err := auth.Exchange(ctx, s.oauth2_config, s.httpClient)
		if err != nil {
			ctx.Writer.Write([]byte(err.Error()))
			return
		}
		session := auth.Login(ctx, token, global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_PUBLIC_PORT, jwk_json_path, nil), nil)
		id := session.Claims["sub"].(string)
		user := s.GetStorage(ctx).GetUserById(id)
		session.Data[session_user_key] = user
		http.Redirect(ctx.Writer, ctx.Request, "/", 302)
	})
	s.engine.GET("/logout", func(ctx *goweb.Context) {
		logout_challenge := ctx.Request.URL.Query().Get("logout_challenge")
		//logout requrest from third-party site
		parameters := url.Values{}
		parameters.Add("logout_challenge", logout_challenge)
		rar := common.NewRestApiRequest("GET", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, LogoutPath, parameters), nil)
		resp, err := s.rac.Do(rar)
		if err != nil {
			panic(err)
		}
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		information := hydraLogoutRequestInformation{}
		err = json.Unmarshal(b, &information)
		if err != nil {
			panic(err)
		}
		rar = common.NewRestApiRequest("PUT", global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_ADMIN_PORT, LogoutPath+"/accept", parameters), nil)
		resp, err = s.rac.Do(rar)
		if err != nil {
			panic(err)
		}
		putRes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		logoutAcceptRes := HydraLogoutAcceptRes{}
		err = json.Unmarshal(putRes, &logoutAcceptRes)
		if err != nil {
			panic(err)
		}
		http.Redirect(ctx.Writer, ctx.Request, logoutAcceptRes.Redirect_to, 302)
	})
	privileged_g.POST("/logout", func(ctx *goweb.Context) {
		//logout requrest from this site itself
		auth.Logout(s.rac, ctx, s.oauth2_config, s.config.Introspect_Token_Url, s.skip_tls_verify, func(id_token string) {
			parameters := url.Values{}
			parameters.Add("id_token_hint", id_token)
			redirect_url := s.config.Post_Logout_Redirect_Uri
			parameters.Add("post_logout_redirect_uri", redirect_url)
			http.Redirect(ctx.Writer, ctx.Request, global.GetUriString(s.config.HYDRA_HOST, s.config.HYDRA_PUBLIC_PORT, sessions_logout_path, parameters), 302)

		})
	})
	s.engine.GET(Api_Path_Introspect_Token, IntrospectTokenHandler(s))
	log.Println("accepting tcp connections on " + s.config.LISTEN_ADDRESS)
	log.Println("website address: https://" + s.config.Website_domain)
	server := http.Server{
		Addr:    s.config.LISTEN_ADDRESS,
		Handler: s.engine,
	}
	err := server.ListenAndServeTLS(s.config.Tls_cert_file, s.config.Tls_key_file)
	if err != nil {
		log.Fatal(err)
	}
}

type HandlerWidget struct {
	s *IDPServer
}

func (*HandlerWidget) Pre_Process(ctx *goweb.Context) {
	log.Println("incomming request:", ctx.Request.URL.Path)
}
func (hw *HandlerWidget) Post_Process(ctx *goweb.Context) {
	m := ctx.Data["storage"]
	if m != nil {
		m.(storage.Storage).Commit()
	}

	if ctx.Err != nil {
		accept := ctx.Request.Header.Get("Accept")
		if strings.Contains(accept, "application/json") {
			ctx.Failed(ctx.Err.Error())
		} else {
			data := struct {
				Desc string
			}{Desc: ctx.Err.Error()}
			model := hw.s.newPageModel(ctx, data)
			model.PageTitle = "ERROR"
			ctx.RenderPage(model, "templates/layout.html", "templates/error.html")
		}
	}
}

type WebSocketMessage struct {
	to      *WebSocketClient
	message []byte
}
type WebSocketHub struct {
	// Registered clients.
	clients  map[*WebSocketClient]bool
	messages chan *WebSocketMessage

	// Register requests from the clients.
	register chan *WebSocketClient

	// Unregister requests from clients.
	unregister chan *WebSocketClient
}

func newWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		clients:    make(map[*WebSocketClient]bool),
		messages:   make(chan *WebSocketMessage),
		register:   make(chan *WebSocketClient),
		unregister: make(chan *WebSocketClient),
	}
}
func (h *WebSocketHub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		case message := <-h.messages:
			client := message.to
			if _, ok := h.clients[client]; ok {
				select {
				case client.send <- message.message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

// Client is a middleman between the websocket connection and the hub.
type WebSocketClient struct {
	hub *WebSocketHub

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan []byte
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (c *WebSocketClient) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
		identifier := "login_challenge"
		if strings.Index(string(message), identifier) != -1 {
			if loginChallenge := findLoginChallenge(string(message)[len(identifier)+1 : len(identifier)+1+32]); loginChallenge != nil {
				if ok, err := loginChallenge.isValid(); !ok {
					log.Println(err)
					continue
				}
				loginChallenge.client = c
				go func() {
					for {
						time.Sleep(time.Second * 30)
						if ok, _ := loginChallenge.isValid(); !ok {
							break
						}
						if loginChallenge.status != 0 {
							break
						}
						qr_code, err := keygenerator.NewKey(internal.VC_LENGTH_QRCODE, false, false, false, true)
						if err != nil {
							panic(err)
						}
						loginChallenge.qrcode = qr_code
						log.Println("send QR code message:" + qr_code)
						c.hub.messages <- &WebSocketMessage{c, []byte("QR:" + qr_code)}
					}
				}()
			}
		}
		//message = bytes.TrimSpace(bytes.Replace(message, newline, space, -1))
	}
}

// writePump pumps messages to the websocket connection.
//
// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (c *WebSocketClient) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// serveWs handles websocket requests from the peer.
func serveWs(hub *WebSocketHub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	client := &WebSocketClient{hub: hub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client

	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go client.writePump()
	go client.readPump()
}

type loginChallenge struct {
	challenge  string
	client     *WebSocketClient
	user       *models.User
	key        string
	created_at time.Time
	qrcode     string
	status     int //0 initial, 1 scanned, 2 accepted, 3 rejected, 4 bad.
}

func (challenge *loginChallenge) update_status(status int) (err error) {
	switch status {
	case 1:
		if challenge.status != 0 {
			err = errors.New("status invalid")
		} else {
			challenge.status = status
		}
		break
	case 2:
		if challenge.status != 1 {
			err = errors.New("status invalid")
		} else {
			challenge.status = status
		}
		break
	case 3:
		if challenge.status != 1 {
			err = errors.New("status invalid")
		} else {
			challenge.status = status
		}
		break
	default:
		err = errors.New("status invalid")
	}
	if err != nil {
		challenge.status = 4
	}
	return err
}
func (challenge *loginChallenge) isValid() (bool, error) {
	if challenge.status == 4 {
		return false, errors.New("bad status")
	}
	diff := challenge.created_at.Sub(time.Now().UTC()).Milliseconds()
	if diff < (-60*5*1000) || diff > (-1) {
		return false, errors.New("timeout")
	}
	return true, nil
}

func registerLoginChallenge(challenge string) {
	login_challenges_mutex.Lock()
	defer login_challenges_mutex.Unlock()
	r := findLoginChallenge(challenge)
	if r != nil {
		panic("request invalid")
	}
	for i := 0; i < len(login_challenges); i++ {
		if ok, _ := login_challenges[i].isValid(); !ok {
			login_challenges = append(login_challenges[:i], login_challenges[i+1:]...)
			i--
		}
	}
	loginChallenge := &loginChallenge{challenge: challenge, client: nil, user: nil, qrcode: "", status: 0, key: "", created_at: time.Now().UTC()}
	login_challenges = append(login_challenges, loginChallenge)
	qr_code, err := keygenerator.NewKey(internal.VC_LENGTH_QRCODE, false, false, false, true)
	if err != nil {
		panic(err)
	}
	loginChallenge.qrcode = qr_code
}
func findLoginChallenge(challenge string) *loginChallenge {
	for _, item := range login_challenges {
		if item.challenge == challenge {
			return item
		}
	}
	return nil
}

var login_challenges = []*loginChallenge{}
var login_challenges_mutex sync.Mutex
