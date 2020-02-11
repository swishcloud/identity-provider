package models

import "time"

type User struct {
	Id                    string
	Name                  string
	Email                 string
	Password              string `json:"-"`
	Avatar                *string
	Email_confirmed       bool
	Email_activation_code *string   `json:"-"`
	Token_valid_after     time.Time `json:"-"`
}
