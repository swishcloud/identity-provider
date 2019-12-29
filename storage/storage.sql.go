package storage

import (
	"database/sql"
	"time"

	"github.com/swishcloud/gostudy/keygenerator"
	"github.com/swishcloud/gostudy/tx"

	"github.com/swishcloud/gostudy/common"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/swishcloud/identity-provider/global"
	"github.com/swishcloud/identity-provider/storage/models"
)

type SQLManager struct {
	Tx *tx.Tx
}

func NewSQLManager(db_conn_info string) *SQLManager {
	db, err := sql.Open("postgres", db_conn_info)
	global.Err(err)
	tx, err := tx.NewTx(db)
	if err != nil {
		panic(err)
	}
	return &SQLManager{Tx: tx}
}
func (m *SQLManager) Commit() {
	m.Tx.Commit()
}
func (m *SQLManager) Rollback() {
	m.Tx.Rollback()
}
func (m *SQLManager) AddUser(username, password, email string) {
	hashedPwd := common.Md5Hash(password)
	code, err := keygenerator.NewKey(50, false, false, false, true)
	global.Err(err)
	m.Tx.MustExec("INSERT INTO public.\"user\"(id, name, email, password,insert_time,email_confirmed, email_activation_code) VALUES ($1,$2,$3,$4,$5,$6,$7)", uuid.New(), username, email, hashedPwd, time.Now().UTC(), 0, code)
}
func (m *SQLManager) DeleteUser() {
}
func (m *SQLManager) UpdateUser() {
}
func (m *SQLManager) GetUsers() {
}
func (m *SQLManager) EmailValidate(email, code string) {
	user := m.GetUserByEmail(email)
	if user == nil {
		panic("the user not found")
	}
	if user.Email_confirmed {
		panic("the user have activated")
	}
	if user.Email_activation_code == nil {
		panic("the user have not email activation code")
	}
	if *user.Email_activation_code != code {
		panic("the email activation code is invalid:" + *user.Email_activation_code)
	}
	m.Tx.MustExec("update public.\"user\" set email_confirmed=true where email=$1", email)
}
func (m *SQLManager) GetUserByEmail(email string) *models.User {
	r := m.Tx.QueryRow("select id,name,email,password,avatar,email_confirmed,email_activation_code from public.\"user\" where email=$1", email)
	return getUser(r)
}
func (m *SQLManager) GetUserByName(name string) *models.User {
	r := m.Tx.QueryRow("select id,name,email,password,avatar,email_confirmed,email_activation_code from public.\"user\" where name=$1", name)
	return getUser(r)
}
func (m *SQLManager) GetUserById(id string) *models.User {
	r := m.Tx.QueryRow("select id,name,email,password,avatar,email_confirmed,email_activation_code from public.\"user\" where id=$1", id)
	return getUser(r)
}
func (m *SQLManager) ChangePassword(id string, newPassword string) {
	hashedPwd := common.Md5Hash(newPassword)
	r := m.Tx.MustExec("update public.\"user\" set password=$1,update_time=$2 where id=$3", hashedPwd, time.Now().UTC(), id)
	n, err := r.RowsAffected()
	global.Err(err)
	if n != 1 {
		panic("change password failed")
	}
}
func getUser(r *sql.Row) *models.User {
	user := models.User{}
	err := r.Scan(&user.Id, &user.Name, &user.Email, &user.Password, &user.Avatar, &user.Email_confirmed, &user.Email_activation_code)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		panic(err)
	}
	return &user
}
