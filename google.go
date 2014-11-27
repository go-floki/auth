package auth

import (
	"code.google.com/p/goauth2/oauth"
	"encoding/json"
	"github.com/go-floki/floki"
	//"github.com/go-floki/sessions"
	"log"
)

type GoogleResponse struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	FirstName     string `json:"given_name"`
	LastName      string `json:"family_name"`
	Link          string `json:"link"`
	Picture       string `json:"picture"`
	Gender        string `json:"gender"`
}

//
func SetupGoogle(r *floki.Floki, store UserStore, options OauthOptions) {
	profileInfoURL := "https://www.googleapis.com/oauth2/v1/userinfo"

	var oauthCfg = &oauth.Config{
		ClientId:     options.AppId,
		ClientSecret: options.AppSecret,

		//For Google's oauth2 authentication, use this defined URL
		AuthURL: "https://accounts.google.com/o/oauth2/auth",

		//For Google's oauth2 authentication, use this defined URL
		TokenURL: "https://accounts.google.com/o/oauth2/token",

		//To return your oauth2 code, Google will redirect the browser to this page that you have defined
		//TODO: This exact URL should also be added in your Google API console for this project within "API Access"->"Redirect URIs"
		RedirectURL: options.RedirectURL,

		//This is the 'scope' of the data that you are asking the user's permission to access. For getting user's info, this is the url that Google has defined.
		Scope: "https://www.googleapis.com/auth/userinfo.email",
	}

	Login := func(c *floki.Context) {
		//Get the Google URL which shows the Authentication page to the user
		url := oauthCfg.AuthCodeURL("")

		c.Redirect(url)
	}

	HandleOauth2Callback := func(c *floki.Context) {
		r := c.Request

		//Get the code from the response
		code := r.FormValue("code")

		t := &oauth.Transport{Config: oauthCfg}

		// Exchange the received code for a token
		t.Exchange(code)

		//now get user data based on the Transport which has the token
		resp, _ := t.Client().Get(profileInfoURL)

		buf := make([]byte, 1024)
		responseLen, _ := resp.Body.Read(buf)

		buf = buf[:responseLen]

		response := GoogleResponse{}
		err := json.Unmarshal(buf, &response)
		if err != nil {
			log.Println("Error unmarshalling:", err)
		}

		user := store.FindByName(response.GetId())
		if user == nil || user.GetName() == "" {
			user = store.Create(response)
		}

		SetUser(c, user)
		c.Redirect("/")
	}

	r.GET("/loginGoogle", Login)
	r.GET("/oauth2/google", HandleOauth2Callback)
}

func (r GoogleResponse) GetId() string {
	return "o:ggl:" + r.Id
}

func (r GoogleResponse) GetFirstName() string {
	return r.FirstName
}

func (r GoogleResponse) GetLastName() string {
	return r.LastName
}

func (r GoogleResponse) GetPicture() string {
	return r.Picture
}

func (r GoogleResponse) GetGender() string {
	return r.Gender
}

func (r GoogleResponse) GetLink() string {
	return r.Link
}

func (r GoogleResponse) GetEmail() string {
	return r.Email
}
