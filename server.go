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
	_ "github.com/mattn/go-sqlite3"
	"github.com/LachlanMac/authorization"
)

type UserSession struct {
	UserName string
	Authenticated bool
	UniqueID string
}

type Character struct {
	ID       int
	Name     string
	X        float64
	Y        float64
	SectorID int
	Model    int
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


func SetupDB(dbName string) *sql.DB {


	db, err := sql.Open("sqlite3", dbName)

	if err != nil{
		fmt.Println("Error Opening SQLITE DB", err)
	}

	return db
}

func AddUser(user authorization.User, db *sql.DB) error{

	sqlStatement := `INSERT INTO users (user_name, email, password)VALUES ($1, $2, $3)`
	_, err := db.Exec(sqlStatement, user.Username, user.Email, user.Password)

	return err
}


func GetCharacter(account_id int, db *sql.DB) (Character, error){


	var id int
	var name string
	var x float64
	var y float64
	var secId int
	var model int

	emptyChar := Character{}

	sqlStatement := `SELECT character_id, character_name, character_model, x_pos, y_pos, sector_id FROM characters WHERE account_id=$1`

	row := db.QueryRow(sqlStatement, account_id)

	err := row.Scan(&id, &name, &model, &x, &y, &secId)

	if err == sql.ErrNoRows {
		return emptyChar, err
	}else if err != nil {
		fmt.Println("Uncaught Server error when attempting to Authorize a User", err)
		return emptyChar, err
	}else{

		char := Character{id, name, x, y, secId, model}
		return char, nil
	}

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
		err = session.Save(req, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false
		}
		return false
	} else{
		if user.UniqueID != authorization.GetUniqueIdentifier(user.UserName){
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
  
	db := SetupDB("/root/database/data.db")
  
 	//e := auth.AuthEngine{db}
  	m.Map(db)

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

	m.Use(func(req *http.Request) {
		if !strings.HasSuffix(req.URL.Path, "/badrequest") && !strings.HasSuffix(req.URL.Path, "/ws/") && !strings.HasSuffix(req.URL.Path, "/favicon.ico") {

		}
	})

	m.Get("/authserver/auth/:user/:password", func(db *sql.DB, r render.Render, params martini.Params, req *http.Request) {

		var username = params["user"]
		var password = params["password"]
		var bytePW = []byte(password)
		user := authorization.User{username, password, "temp"}

		userExists, accountID := authorization.UserExists(user, db)


		if userExists{

			isAuthorized := authorization.Authorize(accountID, bytePW,  db)

			if isAuthorized{

				//get character??

				char, err := GetCharacter(accountID, db)

				if err != nil {
					r.JSON(http.StatusOK, map[string]string{
						"user": user.Username,
						"password": user.Password,
						"id": strconv.Itoa(accountID),
						"status":"nocharacter",
					})
				}else{

					r.JSON(http.StatusOK, map[string]string{
						"name": char.Name,
						"charID": strconv.Itoa(char.ID),
						"sector":strconv.Itoa(char.SectorID),
						"x":strconv.FormatFloat(char.X, 'f', 4, 32),
						"y":strconv.FormatFloat(char.Y, 'f', 4, 32),
						"model":strconv.Itoa(char.Model),
						"user": user.Username,
						"id": strconv.Itoa(accountID),
						"status":"ok",
					})


				}



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

	m.Post("/request-login", func(r render.Render, params martini.Params, req *http.Request, w http.ResponseWriter) {
		//Parse the form generated by the registration page
		req.ParseForm()

		//collect data from form
		username := req.FormValue("user")
		password := req.FormValue("pwd")

		fmt.Println(username, password)


		user := authorization.User{username, password, "temp"}


		userExists, accountID := authorization.UserExists(user, db)

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

			isAuthorized := authorization.Authorize(accountID, bytePW,  db)

			fmt.Println("AUTHORIZATION STATUS = ", isAuthorized)

			userSession := &UserSession{username,true, authorization.GetUniqueIdentifier(username)}

			session, _ := store.Get(req, "cookie-name")

			session.Values["user"] = userSession

			err := session.Save(req, w)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
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
		hashsalt := authorization.GenerateHashSalt(password)
		//create user struct
		user := authorization.User{username, hashsalt, emailAddress}

		successfulRegistration := true

		userExists, _ := authorization.UserExists(user, db)
		emailExists := authorization.EmailExists(user, db)

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

	http.ListenAndServe(":80", m)
}




