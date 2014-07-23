package auth

import (
	"github.com/go-floki/floki"
	"github.com/go-floki/sessions"
)

type UserStore interface {
	FindByName(name string) User
}

//
func Setup(r *floki.Floki, store UserStore) {

	//
	// Bind it to POST /login
	Login := func(c *floki.Context) {
		req := c.Request

		name := req.PostFormValue("name")
		password := req.PostFormValue("password")

		user := store.FindByName(name)

		// check if hash matches the one which we have in DB
		if user != nil && ValidatePassword(password, user.GetPassword()) {
			SetUser(c, user)
			c.Redirect("/")

		} else {
			sessions.Get(c).AddFlash("Failed to login as " + name + ". Invalid name or password.")
			c.Redirect("/login")
		}

	}

	//
	// Bind it to GET /logout
	Logout := func(c *floki.Context) {
		ClearUser(c)
		c.Redirect("/login")
	}

	r.POST("/login", Login)
	r.GET("/logout", Logout)
}
