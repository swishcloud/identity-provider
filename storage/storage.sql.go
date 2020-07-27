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

var db *sql.DB

func NewSQLManager(db_conn_info string) *SQLManager {
	if db == nil {
		if d, err := tx.NewDB("postgres", db_conn_info); err != nil {
			panic(err)
		} else {
			db = d
		}
	}
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
	global.Panic(err)
	m.Tx.MustExec("INSERT INTO public.\"user\"(id, name, email, password,insert_time,email_confirmed, email_activation_code,avatar,token_valid_after,failure_num) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,0)", uuid.New(), username, email, hashedPwd, time.Now().UTC(), 0, code, "", time.Now().UTC())
}
func (m *SQLManager) DeleteUser() {
}
func (m *SQLManager) ZeroLoginFailureNum(userId string) {
	m.Tx.MustExec("update public.\"user\" set failure_num=0 where id=$1", userId)
}
func (m *SQLManager) UpdateLockTimestamp(userId string) {
	m.Tx.MustExec("update public.\"user\" set lock_timestamp=$1 where id=$2", time.Now().UTC(), userId)
}
func (m *SQLManager) IncreaseLoginFailureNum(userId string) {
	m.Tx.MustExec("update public.\"user\" set failure_num=failure_num+1 where id=$1", userId)
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
	return m.getUser("where email=$1", email)
}
func (m *SQLManager) GetUserByName(name string) *models.User {
	return m.getUser("where name=$1", name)
}
func (m *SQLManager) GetUserById(id string) *models.User {
	return m.getUser("where id=$1", id)
}
func (m *SQLManager) ChangePassword(id string, newPassword string) {
	hashedPwd := common.Md5Hash(newPassword)
	r := m.Tx.MustExec("update public.\"user\" set password=$1,update_time=$2,token_valid_after=$3 where id=$4", hashedPwd, time.Now().UTC(), time.Now().UTC(), id)
	n, err := r.RowsAffected()
	global.Panic(err)
	if n != 1 {
		panic("change password failed")
	}
}
func (m *SQLManager) getUser(where string, args ...interface{}) *models.User {
	r := m.Tx.QueryRow("select id,name,email,password,avatar,email_confirmed,email_activation_code,token_valid_after,failure_num,lock_timestamp from public.\"user\" "+where, args...)
	user := models.User{}
	err := r.Scan(&user.Id, &user.Name, &user.Email, &user.Password, &user.Avatar, &user.Email_confirmed, &user.Email_activation_code, &user.Token_valid_after, &user.Failure_num, &user.Lock_timestamp)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		panic(err)
	}
	return &user
}
