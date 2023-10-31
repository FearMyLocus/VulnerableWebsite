package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type Credentials struct {
	Username string
	Password string
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/login", LoginHandler).Methods("POST")
	r.HandleFunc("/egvuiub3iub_AdminLogin", requireAuth(AdminHandler, "admin"))
	r.HandleFunc("/some_random_string_for_user", requireAuth(UserHandler, "user"))
	r.HandleFunc("/email_login", EmailLoginHandler)
	secureHandler := setSecurityHeaders(r)
	http.Handle("/", secureHandler)
	fmt.Println("Server is running at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func requireAuth(inner http.HandlerFunc, allowedRole string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, ok := users[cookie.Value]
		if !ok || user.Role != allowedRole {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		inner.ServeHTTP(w, r)
	})
}

func setSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; object-src 'none';")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		next.ServeHTTP(w, r)
	})
}

type User struct {
	Username      string
	PasswordHash  string
	Role          string
	Email         string
	EmailPassword string
	SecurityQn    string
	SecurityAns   string
}

var users = make(map[string]User)

func init() {
	addUser("admin", "password123", "admin", "admin@example.com", "adminEmailPassword", "What is your favorite color?", "Blue")
	addUser("user1", "userpassword", "user", "user1@example.com", "user1EmailPassword", "What is your favorite pet?", "Dog")
}

func addUser(username, password, role, email, emailPassword, securityQn, securityAns string) {
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	users[username] = User{
		Username:      username,
		PasswordHash:  string(passwordHash),
		Role:          role,
		Email:         email,
		EmailPassword: emailPassword,
		SecurityQn:    securityQn,
		SecurityAns:   securityAns,
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	errorMsg := r.URL.Query().Get("error")
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, map[string]string{"Error": errorMsg})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		// Redirect back to login page with error message
		http.Redirect(w, r, "/?error=Invalid+Username.+or+password+please+try+again.", http.StatusSeeOther)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    username,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		MaxAge:   3600,
	})

	if user.Role == "admin" {
		http.Redirect(w, r, "/egvuiub3iub_AdminLogin", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/some_random_string_for_user", http.StatusSeeOther)
	}
}

func UserHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/user.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, ok := users[cookie.Value]
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tmpl.Execute(w, map[string]string{"Username": user.Username, "SecurityQn": user.SecurityQn})
}

func AdminHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/admin.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	tableRows := ""
	for username, user := range users {
		tableRows += fmt.Sprintf("<tr><td>%s</td><td>%s</td></tr>", username, user.PasswordHash)
	}
	tmpl.Execute(w, map[string]interface{}{"TableRows": template.HTML(tableRows)})
}

func EmailLoginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/email_login.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}
