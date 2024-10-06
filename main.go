package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

var users = map[string]Login{}

func main() {
	http.HandleFunc("/register", Register)
	http.HandleFunc("/login", Logins)
	http.HandleFunc("/logout", Logout)
	http.HandleFunc("/protected", Protected)
	fmt.Println("Server is running on :8080")
	http.ListenAndServe(":8080", nil)
}
func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		err := http.StatusMethodNotAllowed
		http.Error(w, "Invalid Method", err)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(username) < 5 || len(password) < 8 {
		http.Error(w, "Invalid username or password", http.StatusBadRequest)
		return
	}

	if _, ok := users[username]; ok {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	}

	hashedPassword, _ := HashedPassword(password)
	users[username] = Login{
		HashedPassword: hashedPassword,
		SessionToken:   "",
		CSRFToken:      "",
	}
	fmt.Fprintln(w, "Registration successful")

}

func Logins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		err := http.StatusMethodNotAllowed
		http.Error(w, "Invalid Method", err)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok || !CheckPasswordHash(password, user.HashedPassword) {
		http.Error(w, "Invalid username or password", http.StatusBadRequest)
		return
	}

	sessionToken := GenerateToken(32)
	csrfToken := GenerateToken(32)

	//set csrf token
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
	})

	//set coockie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	fmt.Fprintln(w, "Login successful")

}

func Logout(w http.ResponseWriter, r *http.Request) {
	if err := Authorized(r); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// clear session token
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})

	//clear csrf token
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	// clear the token from database
	username := r.FormValue("username")
	user, ok := users[username]
	if ok {
		user.SessionToken = ""
		user.CSRFToken = ""
		users[username] = user
	}

	fmt.Fprintln(w, "Logout successful")

}

func Protected(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		err := http.StatusMethodNotAllowed
		http.Error(w, "Invalid Method", err)
		return
	}

	if err := Authorized(r); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	username := r.FormValue("username")

	fmt.Fprintf(w, "CSRF Validation successful for user: %s", username)

}
