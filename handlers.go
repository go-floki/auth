package auth

import (
	"github.com/go-floki/floki"
	"github.com/go-floki/sessions"
)

//
func Setup(r *floki.Floki, store UserStore) {

	//
	// Bind it to POST /login
	Login := func(c *floki.Context) {
		req := c.Request

		name := req.PostFormValue("name")
		password := req.PostFormValue("password")

		user := store.FindByName(name)

		if floki.Env == floki.Dev {
			c.Logger().Println("Checking password for", name, "found user entry:", user)
		}

		// check if hash matches the one which we have in DB
		if user != nil && ValidatePassword(password, user.GetPassword()) {
			if floki.Env == floki.Dev {
				c.Logger().Println("Logged in user:", name)
			}

			SetUser(c, user)
			c.Redirect("/")

		} else {
			if floki.Env == floki.Dev {
				c.Logger().Println("User", name, "not found or passwords don't match")
			}

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
