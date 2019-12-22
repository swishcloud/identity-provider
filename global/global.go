package global

import (
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func GetUriString(host, port string, is_https bool, path string, urlParameters url.Values) string {
	var scheme string
	if is_https {
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
