package main

import (
	"github.com/go-martini/martini"
	"database/sql"
	"fmt"
	"html/template"
	"strings"
	"strconv"
	"net/http"
	"encoding/gob"
	"github.com/gorilla/sessions"
	"github.com/martini-contrib/render"
	"github.com/martini-contrib/secure"
	_ "github.com/go-sql-driver/mysql"
	"github.com/LachlanMac/lcrypto"

	"golang.org/x/crypto/bcrypt"
)

type UserSession struct {
	UserName string
	Authenticated bool
	UniqueID string
}
type User struct {

	Username string
	Password string
	Email string
}


type Character struct {
	ID       int
	Name     string
	X        float64
	Y        float64
	SectorID int
	Model    string
	Layer    int
	Faction  int
	Structure int
}





var(
	key = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

func getUser(s *sessions.Session) UserSession {
	val := s.Values["user"]
	var user = UserSession{}
	user, ok := val.(UserSession)
	if !ok {
		return UserSession{Authenticated: false}
	}
	return user
}

func ServerInit(){

	store.Options = &sessions.Options{
		MaxAge:   0,
		HttpOnly: true,
	}

	gob.Register(UserSession{})
}


func SetupDB() *sql.DB {

	db, err := sql.Open("mysql", "root:Movingon1@/starmyth")


	if err != nil{
		fmt.Println("Error Opening Mysql DB", err)
	}

	return db
}



func isVerified(req *http.Request, w http.ResponseWriter) bool{

	//CUSTOM
	session, err := store.Get(req, "cookie-name")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}

	user := getUser(session)

	auth := user.Authenticated

	if auth == false{
		session.Options.MaxAge = -1
		err = session.Save(req, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false
		}
		return false
	} else{
		if user.UniqueID != GetUniqueIdentifier(user.UserName){
			fmt.Println("User :", user.UserName, "has an invalid session unique identifier")
			return false
		}else{
			return true
		}
	}
}




func main() {

	ServerInit()

	m := martini.Classic()

	db := SetupDB()

	m.Map(db)

	martini.Env = martini.Prod

	helpers := template.FuncMap{
		"print": fmt.Println,
	}

	//Setup martini options
	m.Use(render.Renderer(render.Options{
		Directory:  "public",
		Layout:     "html/layouts/default",
		Extensions: []string{".html"},
		Funcs: []template.FuncMap{
			helpers,
		},
	}))

	m.Use(secure.Secure(secure.Options{
		SSLRedirect: false,
		SSLHost:     "localhost:8443",
	}))

	m.Use(func(req *http.Request) {
		if !strings.HasSuffix(req.URL.Path, "/badrequest") && !strings.HasSuffix(req.URL.Path, "/ws/") && !strings.HasSuffix(req.URL.Path, "/favicon.ico") {

		}
	})


	m.Get("/", func(db *sql.DB, r render.Render, req *http.Request, w http.ResponseWriter) {
		hasSession := isVerified(req, w)
		newmap := map[string]interface{}{
			"hasSession" : hasSession,
		}

		r.HTML(http.StatusOK, "html/pages/index", newmap)

	})

	m.Get("/login", func(db *sql.DB, r render.Render,req *http.Request, w http.ResponseWriter) {


		hasSession := isVerified(req, w)

		newmap := map[string]interface{}{
			"hasSession" : hasSession,
		}

		r.HTML(http.StatusOK, "html/pages/login", newmap)

	})

	m.Get("/account", func(db *sql.DB, r render.Render,req *http.Request, w http.ResponseWriter) {


		hasSession := isVerified(req, w)

		newmap := map[string]interface{}{
			"hasSession" : hasSession,
		}

		r.HTML(http.StatusOK, "html/pages/account", newmap)

	})

	m.Get("/features", func(r render.Render, params martini.Params, req *http.Request, w http.ResponseWriter) {

		hasSession := isVerified(req, w)
		//END CUSTOM

		newmap := map[string]interface{}{
			"hasSession" : hasSession,
		}

		r.HTML(http.StatusOK, "html/pages/features", newmap)

	})

	m.Get("/register", func(db *sql.DB, r render.Render, req *http.Request, w http.ResponseWriter) {

		hasSession := isVerified(req, w)
		username := ""
		emailAddress := ""
		newmap := map[string]interface{}{
			"user" : username,
			"email" : emailAddress,
			"hasSession" : hasSession,
		}

		r.HTML(http.StatusOK, "html/pages/registration", newmap)

	})

	m.Get("/status", func(db *sql.DB, r render.Render, req *http.Request, w http.ResponseWriter) {

		hasSession := isVerified(req, w)
		newmap := map[string]interface{}{
			"hasSession" : hasSession,
		}

		r.HTML(http.StatusOK, "html/pages/status", newmap)

	})

	m.Get("/download", func(db *sql.DB, req *http.Request, w http.ResponseWriter, r render.Render) {
		hasSession := isVerified(req, w)
		newmap := map[string]interface{}{
			"hasSession" : hasSession,
		}

		r.HTML(http.StatusOK, "html/pages/download", newmap)

	})


	m.Get("/download/client", func(db *sql.DB, req *http.Request, w http.ResponseWriter, r render.Render) {

		header := w.Header()
		header.Add("Content-Type", "application/octet-stream")
		header.Add("Content-Disposition", "attachment; filename=\"client.zip\"")

		http.ServeFile(w, req, "/client/client.zip")

	})



	m.Post("/request-login", func(r render.Render, params martini.Params, req *http.Request, w http.ResponseWriter) {
		//Parse the form generated by the registration page
		req.ParseForm()

		//collect data from form
		username := req.FormValue("user")
		password := req.FormValue("pwd")


		user := User{username, password, "temp"}


		userExists, accountID := UserExists(user, db)

		if userExists == false{
			//bytePW := []byte(user.Password)
			//check if awaiting authorization
			//awaitingAuth, email := authorization.AwaitingAuthorization(accountID, bytePW, db)
			awaitingAuth := false
			if awaitingAuth {

				//account not verified?  Resend email???
				//fmt.Println("Awaiting verification ", email)

			}else{

				fmt.Println("User does not exist")
			}

		}else{

			bytePW := []byte(user.Password)

			isAuthorized := Authorize(accountID, bytePW,  db)

			fmt.Println("AUTHORIZATION STATUS = ", isAuthorized)

			if isAuthorized {

				userSession := &UserSession{username, true, GetUniqueIdentifier(username)}

				session, _ := store.Get(req, "cookie-name")

				session.Values["user"] = userSession
				err := session.Save(req, w)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}else{

				r.JSON(http.StatusInternalServerError,map[string]string{
					"type":   "loginError",
					"reason": "not authorized",
				})

			}

		}
	})


	m.Post("/request-registration", func(r render.Render, params martini.Params, req *http.Request, w http.ResponseWriter){
		//Parse the form generated by the registration page
		req.ParseForm()

		//collect data from form
		username := req.FormValue("user")
		password := req.FormValue("pwd")
		emailAddress := req.FormValue("email")
		//generate hashsalt out of password
		hashsalt := GenerateHashSalt(password)
		//create user struct
		user := User{username, hashsalt, emailAddress}

		successfulRegistration := true

		userExists, _ := UserExists(user, db)
		emailExists := EmailExists(user, db)

		if userExists == true || emailExists == true {
			successfulRegistration = false
		}

		if !successfulRegistration{

			errorReason := ""


			if userExists {
				errorReason = "This Username is already registered."
			}
			if emailExists{
				errorReason = "This Email Address is already registered."
			}

			r.JSON(http.StatusBadRequest, map[string]string{
				"type":   "registrationError",
				"reason": errorReason,
			})

		}else{
			err := AddUser(user, db)

			if err != nil{

				fmt.Println(err)

				r.JSON(http.StatusInternalServerError,map[string]string{
					"type":   "registrationError",
					"reason": "internal server error",
				})
			}
		}
	})

	m.Post("/logout", func(params martini.Params, req *http.Request, w http.ResponseWriter) {

		session, err := store.Get(req, "cookie-name")

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Values["user"] = UserSession{}
		session.Options.MaxAge = -1
		err = session.Save(req, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, "/", http.StatusFound)
	})





	m.Get("/create-character/:id/:name/:model", func(db *sql.DB, r render.Render, params martini.Params, req *http.Request, w http.ResponseWriter){

		accountID := params["id"]
		charname := params["name"]
		model := params["model"]

		charNameExists, err := CharNameExists(charname, db)

		if charNameExists == false && err == nil {


			id, _ := strconv.Atoi(accountID)

			err := AddCharacter(id, charname, model,  db)


			if err == nil {
				r.JSON(http.StatusOK, map[string]string{
					"status": "success",
				})
			}else{
				r.JSON(http.StatusOK, map[string]string{
					"status": "failed",
				})
			}
		}else{
			r.JSON(http.StatusOK, map[string]string{
				"status": "charnameexists",
			})

		}

	})


	m.Get("/authserver/auth/:user/:password", func(db *sql.DB, r render.Render, params martini.Params, req *http.Request) {

		username, _ := lcrypto.Decrypt(params["user"])
		password, _ := lcrypto.Decrypt(params["password"])


		var bytePW = []byte(password)
		user := User{username, password, "temp"}

		userExists, accountID := UserExists(user, db)

		if userExists{

			isAuthorized :=Authorize(accountID, bytePW,  db)

			if isAuthorized{

				char, err := GetCharacter(accountID, db)
				if err != nil{
					fmt.Println("Error Getting Character", err)
				}

				r.JSON(http.StatusOK, map[string]string{
					"charid":strconv.Itoa(char.ID),
					"name":char.Name,
					"x":strconv.FormatFloat(char.X, 'f', 4, 64),
					"y":strconv.FormatFloat(char.Y, 'f', 4, 64),
					"sector":strconv.Itoa(char.SectorID),
					"model":char.Model,
					"layer":strconv.Itoa(char.Layer),
					"faction":strconv.Itoa(char.Faction),
					"structure":strconv.Itoa(char.Structure),

				})


			}else{
				r.JSON(http.StatusOK, map[string]string{
					"status":"not-authorized",
				})
			}

		}else{

			r.JSON(http.StatusOK, map[string]string{
				"status":"invalid-user",
			})

		}
	})

	http.ListenAndServe(":80", m)




}

func CharNameExists(charName string,  db *sql.DB) (bool, error){


	sqlStatement := `SELECT character_id FROM characters WHERE character_name=$1`


	rows, err := db.Query(sqlStatement, charName)

	if err != nil{

		fmt.Println("ERROR checking charname")
		return true, err
	}


	var id int


	var exists bool

	for rows.Next() {
		err = rows.Scan(&id)
		exists = true
	}

	rows.Close()

	return exists, err

}

func AddCharacter(account_id int, character_name string, model string,  db *sql.DB) (error) {

	sqlStatement := `INSERT INTO PlayerCharacter (account_id, character_name, character_model, local_x, local_y, sector_id, layer, faction_id, structure_id)VALUES (?,?,?,?,?,?,?,?,?)`
	_, err := db.Exec(sqlStatement, account_id, character_name, model, 4000, 4000, 7780, 1,1,1001)

	fmt.Println("error Addking character", err)
	return err

}


func GetCharacter(account_id int, db *sql.DB) (Character, error){


	sqlStatement := `SELECT character_id, character_name, character_model, local_x, local_y, sector_id, layer, faction_id, structure_id FROM PlayerCharacter WHERE account_id=?`

	rows, err := db.Query(sqlStatement, account_id)
	if err != nil {
		fmt.Println("ERROR OCCURED", err)
	}
	defer rows.Close()

	var char Character

	for rows.Next(){

		var id int
		var name string
		var x float64
		var y float64
		var secId int
		var model string
		var layer int
		var faction int
		var structure int


		err := rows.Scan(&id, &name, &model, &x, &y, &secId, &layer, &faction, &structure)

		if err == nil{


			char = Character{id, name, x, y, secId, model, layer, faction, structure}



		}else{

			fmt.Println("Error reading rows", err)
		}

	}

	return char, err

}


func AddUser(user User, db *sql.DB) error{

	sqlStatement := `INSERT INTO Account (username, email, password, joindate, status)VALUES (?, ?, ?,  current_timestamp(), 1)`
	_, err := db.Exec(sqlStatement, user.Username, user.Email, user.Password)



	accountID, err := GetAccountID(user, db)

	if err == nil{
		fmt.Println("adding default character")
		AddCharacter(accountID, user.Username, "ffffeeee00002222", db)

	}

	return err
}

func GetAccountID(user User, db *sql.DB) (int, error){

	var account_id int
	sqlStatement := `SELECT account_id FROM Account WHERE username=?`
	row := db.QueryRow(sqlStatement, user.Username)

	err := row.Scan(&account_id)

	if err == sql.ErrNoRows {
		return 0, err
	}else if err != nil {
		fmt.Println("Uncaught Server error when attempting to check if an Email Address exists", err)
		return 0, err
	}else{
		return account_id, err
	}


}




func GetUniqueIdentifier(username string) string {

	code := 71923

	for index, char := range username {
		code += (int(char) + index)
	}

	uniqueID := code / 2 + ((code + 2) * 2)

	uniqueString := strconv.Itoa(uniqueID)

	return uniqueString

}


func GenerateHashSalt(password string) string{

	passwordSlice := []byte(password)
	hash, err := bcrypt.GenerateFromPassword(passwordSlice, bcrypt.MinCost)
	if err != nil {
		fmt.Println(err)
	}

	return string(hash)

}

func VerifyHashedPassword(hashedPassword string, plainTextPassword []byte) bool{


	byteHash := []byte(hashedPassword)

	err := bcrypt.CompareHashAndPassword(byteHash, plainTextPassword)

	if err == nil{
		return true
	}else{
		return false
	}

}


func Authorize(account_id int, plainTextPassword []byte, db *sql.DB) bool {

	var password string
	sqlStatement := `SELECT password FROM Account WHERE account_id=?`
	row := db.QueryRow(sqlStatement, account_id)

	err := row.Scan(&password)

	if err == sql.ErrNoRows {
		return false
	}else if err != nil {
		fmt.Println("Uncaught Server error when attempting to Authorize a User", err)
		return false
	}else{
		return VerifyHashedPassword(password, plainTextPassword)
	}

}

func AwaitingAuthorization(account_id int, plainTextPassword []byte, db *sql.DB) (bool, string) {

	var password string
	var email string
	sqlStatement := `SELECT password, email FROM unverified_users WHERE account_id=?`
	rows := db.QueryRow(sqlStatement, account_id)

	err := rows.Scan(&password, &email)

	if err == sql.ErrNoRows {
		return false, "nil"
	}else if err != nil {
		fmt.Println("Uncaught Server error when attempting to Authorize a User", err)
		return false, "nil"
	}else{
		return VerifyHashedPassword(password, plainTextPassword), email
	}
}


/*
`account_id` int(10) NOT NULL AUTO_INCREMENT,
`username` VARCHAR(255),
`email` VARCHAR(255),
`password` VARCHAR(255),
`joindate` DATE,
`status` int(1),
PRIMARY KEY (`account_id`),
UNIQUE KEY `email` (`email`)
*/

func UserExists(user User, db *sql.DB) (bool, int){

	var account_id int
	sqlStatement := `SELECT account_id FROM Account WHERE username=?`
	row := db.QueryRow(sqlStatement, user.Username)

	err := row.Scan(&account_id)

	if err == sql.ErrNoRows {
		return false, 0
	}else if err != nil {
		fmt.Println("Uncaught Server error when attempting to check if a User exists", err)
		return true, 0
	}else{

		return true, account_id
	}
}

func EmailExists(user User, db *sql.DB) bool{

	var account_id int
	sqlStatement := `SELECT account_id FROM Account WHERE email=?`
	row := db.QueryRow(sqlStatement, user.Email)

	err := row.Scan(&account_id)

	if err == sql.ErrNoRows {
		return false
	}else if err != nil {
		fmt.Println("Uncaught Server error when attempting to check if an Email Address exists", err)
		return true
	}else{
		return true
	}

}

