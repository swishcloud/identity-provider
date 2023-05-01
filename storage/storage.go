package storage

import "github.com/swishcloud/identity-provider/storage/models"

type Storage interface {
	AddUser(username, password, email string)
	AddClientCredentials(clientid, name, password string)
	DeleteUser()
	ZeroLoginFailureNum(userId string)
	UpdateLockTimestamp(userId string)
	IncreaseLoginFailureNum(userId string)
	UpdateUser()
	UpdateUserVerificationCode(userId string, verification_code *string)
	GetUsers() []map[string]interface{}
	GetUserByEmail(email string) *models.User
	GetUserByName(name string) *models.User
	GetUserById(name string) *models.User
	Commit()
	Rollback()
	EmailValidate(email, code string)
	ChangePassword(id string, newPassword string)
}
