package global

import (
	"net"
	"net/url"
	"strings"
)

func GetUriString(host, port string, path string, urlParameters url.Values) string {
	if urlParameters != nil {
		if strings.Index(path, "?") == -1 {
			path = path + "?"
		} else {
			path = path + "&"
		}
	}
	return "https://" + net.JoinHostPort(host, port) + path + urlParameters.Encode()
}
func Panic(err error) {
	if err != nil {
		panic(err)
	}
}
