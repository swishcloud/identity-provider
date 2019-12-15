package storage

import (
	"database/sql"
	"time"

	"github.com/swishcloud/gostudy/common"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/swishcloud/identity-provider/global"
	"github.com/swishcloud/identity-provider/storage/models"
)

type SQLManager struct {
	DB *sql.DB
}

func NewSQLManager() *SQLManager {
	db, err := sql.Open("postgres", global.Config.DB_CONN_INFO)
	global.Err(err)
	return &SQLManager{DB: db}
}
func (m *SQLManager) AddUser(username, password, email string) {
	hashedPwd := common.Md5Hash(password)
	_, err := m.DB.Query("INSERT INTO public.\"user\"(id, name, email, password,insert_time) VALUES ($1,$2,$3,$4,$5)", uuid.New(), username, email, hashedPwd, time.Now().UTC())
	global.Err(err)
}
func (m *SQLManager) DeleteUser() {
}
func (m *SQLManager) UpdateUser() {
}
func (m *SQLManager) GetUsers() {
}

func (m *SQLManager) GetUserByName(name string) *models.User {
	r := m.DB.QueryRow("select id,name,password from public.\"user\" where name=$1", name)
	return getUser(r)
}
func (m *SQLManager) GetUserById(id string) *models.User {
	r := m.DB.QueryRow("select id,name,password from public.\"user\" where id=$1", id)
	return getUser(r)
}
func getUser(r *sql.Row) *models.User {
	user := models.User{}
	err := r.Scan(&user.Id, &user.Name, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		panic(err)
	}
	return &user
}
