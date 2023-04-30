package models

import "time"

type User struct {
	Id                                 string
	Name                               string
	Email                              string
	Avatar                             *string
	Role                               int        // 1, normal user; 2, administrator user
	Password                           string     `json:"-"`
	Email_confirmed                    bool       `json:"-"`
	Email_activation_code              *string    `json:"-"`
	Verification_code                  *string    `json:"-"`
	Verification_code_update_timestamp *time.Time `json:"-"`
	Token_valid_after                  time.Time  `json:"-"`
	Failure_num                        int        `json:"-"`
	Lock_timestamp                     *time.Time `json:"-"`
}

func (user User) IsAdmin() bool {
	return user.Role == 2
}
