package storage

import "github.com/swishcloud/identity-provider/storage/models"

type Storage interface {
	AddUser(username, password, email string)
	DeleteUser()
	UpdateUser()
	GetUsers()
	GetUserByName(name string) *models.User
	GetUserById(name string) *models.User
	Commit()
	Rollback()
	EmailValidate(email, code string)
	ChangePassword(id string, newPassword string)
}
