package global

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

var Config config

type config struct {
	HYDRA_ADMIN_HOST  string `yaml:"hydra_admin_host"`
	HYDRA_PUBLIC_HOST string `yaml:"hydra_public_host"`
	IS_HTTPS          bool   `yaml:"is_https"`
	LISTEN_ADDRESS    string `yaml:"listen_address"`
	WEBSITE_NAME      string `yaml:"website_name"`
	SECRET            string `yaml:"secret"`
	DB_CONN_INFO      string `yaml:"db_conn_info"`
}

const (
	IDENTITY_PROVIDER_CONFIG = "IDENTITY_PROVIDER_CONFIG"
)

func init() {
	if path, ok := os.LookupEnv(IDENTITY_PROVIDER_CONFIG); ok {
		b, err := ioutil.ReadFile(path)
		if err != nil {
			panic(err)
		}
		err = yaml.Unmarshal(b, &Config)
		if err != nil {
			panic(err)
		}
	} else {
		log.Fatal("missing required environment variable " + IDENTITY_PROVIDER_CONFIG)
	}
}

func GetUriString(host string, path string, urlParameters url.Values) string {
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
	return scheme + "://" + host + path + urlParameters.Encode()
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
