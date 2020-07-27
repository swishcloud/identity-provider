package storage

import "github.com/swishcloud/identity-provider/storage/models"

type Storage interface {
	AddUser(username, password, email string)
	DeleteUser()
	ZeroLoginFailureNum(userId string)
	UpdateLockTimestamp(userId string)
	IncreaseLoginFailureNum(userId string)
	UpdateUser()
	GetUsers()
	GetUserByName(name string) *models.User
	GetUserById(name string) *models.User
	Commit()
	Rollback()
	EmailValidate(email, code string)
	ChangePassword(id string, newPassword string)
}
