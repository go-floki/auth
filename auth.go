package auth

import (
	"log"
	//"net/http"
	"github.com/go-floki/floki"
	"github.com/go-floki/sessions"
	"github.com/jameskeane/bcrypt"
)

const (
	ROLE_ADMIN int = iota
	ROLE_REGISTERED
	ROLE_ANONYMOUS
)

type User interface {
	GetName() string
	GetPassword() string
	GetRole() int
}

type UserStore interface {
	FindByName(name string) User
	Create(user OauthProfile) User
}

func SetUser(c *floki.Context, user User) {
	session := sessions.Get(c)
	session.Set("user", user)
}

func ClearUser(c *floki.Context) {
	session := sessions.Get(c)
	session.Delete("user")
}

func Auth(neededRole int, redirectUrl string) floki.HandlerFunc {
	return func(c *floki.Context) {
		//l := c.Logger()

		session := sessions.Get(c)
		userValue := session.Get("user")
		role := ROLE_ANONYMOUS

		if userValue != nil {
			user := userValue.(User)

			if HasToRefresh(user.GetName()) {
				session.Delete("user")
				c.Redirect("/login")
				return

			} else {
				role = user.GetRole()
			}

		} else {
			//l.Println("user not logged in!")
		}

		if neededRole >= role {
			c.Next()
		} else {
			c.Redirect("/login")
		}
	}
}

var salt = "$2a$12$LAJTpa/DgczR4x8RpVsLQO"

func Hash(password string) string {
	hash, err := bcrypt.Hash(password, salt)

	if err != nil {
		log.Println("error hashing password:", err)
	}

	return hash
}

func ValidatePassword(password string, hash string) bool {
	return bcrypt.Match(password, hash)
}
