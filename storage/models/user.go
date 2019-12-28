package models

type User struct {
	Id                    string
	Name                  string
	Email                 string
	Password              string
	Avatar                *string
	Email_confirmed       bool
	Email_activation_code *string
}
