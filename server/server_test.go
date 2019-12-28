package server

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/swishcloud/identity-provider/storage"
)

const config_path = "/workspace/go/src/github.com/swishcloud/identity-provider/config.yaml"

func TestRegisterHandler(t *testing.T) {
	s := NewIDPServer(config_path)
	s.engine.POST("/register", RegisterHandler(s))
	ts := httptest.NewTLSServer(s.engine)
	defer ts.Close()
	req := httptest.NewRequest("POST", ts.URL+"/register", nil)
	req.PostForm = url.Values{}
	req.PostForm.Add("username", "test")
	req.PostForm.Add("password", "test_secret")
	req.PostForm.Add("confirmPassword", "test_secret")
	req.PostForm.Add("email", "flwwd@outlook.com")
	req.PostForm.Add("send_email", "0")
	w := httptest.NewRecorder()
	s.engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Error("status:", w.Code)
	}
	_, err := loginAuthenticate(storage.NewSQLManager(s.config.DB_CONN_INFO), "test", "test_secret")
	if err == nil {
		t.Error("this login attempt shoudn't have succeeded")
	} else {
		fmt.Println(err)
	}
}
