package global

import (
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var Config config

type config struct {
	HYDRA_HOST               string `yaml:"hydra_host"`
	HYDRA_PUBLIC_PORT        string `yaml:"hydra_public_port"`
	HYDRA_ADMIN_PORT         string `yaml:"hydra_admin_port"`
	IS_HTTPS                 bool   `yaml:"is_https"`
	LISTEN_ADDRESS           string `yaml:"listen_address"`
	WEBSITE_NAME             string `yaml:"website_name"`
	SECRET                   string `yaml:"secret"`
	DB_CONN_INFO             string `yaml:"db_conn_info"`
	Post_Logout_Redirect_Uri string `yaml:"post_logout_redirect_uri"`
}

func init() {

}

func GetUriString(host, port string, path string, urlParameters url.Values) string {
	var scheme string
	if Config.IS_HTTPS {
		scheme = "https"
	} else {
		scheme = "http"
	}
	if urlParameters != nil {
		if strings.Index(path, "?") == -1 {
			path = path + "?"
		} else {
			path = path + "&"
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port) + path + urlParameters.Encode()
}

func SendRestApiRequest(method string, urlPath string, body []byte) []byte {
	headers := map[string][]string{
		"Content-Type": []string{"application/x-www-form-urlencoded"},
		"Accept":       []string{"application/json"},
	}
	req, err := http.NewRequest(method, urlPath, bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}
	req.Header = headers

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return b
}
func Err(err error) {
	if err != nil {
		panic(err)
	}
}
