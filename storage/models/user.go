package models

import "time"

type User struct {
	Id                                 string
	Name                               string
	Email                              string
	Avatar                             *string
	Password                           string     `json:"-"`
	Email_confirmed                    bool       `json:"-"`
	Email_activation_code              *string    `json:"-"`
	Verification_code                  *string    `json:"-"`
	Verification_code_update_timestamp *time.Time `json:"-"`
	Token_valid_after                  time.Time  `json:"-"`
	Failure_num                        int        `json:"-"`
	Lock_timestamp                     *time.Time `json:"-"`
}
