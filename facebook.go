package auth

import (
	"code.google.com/p/goauth2/oauth"
	"encoding/json"
	"github.com/go-floki/floki"
	//"github.com/go-floki/sessions"
	"log"
	"net/http"
	"net/url"
)

type FacebookResponse struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Link          string `json:"link"`
	Picture       string `json:"picture"`
	Gender        string `json:"gender"`
}

//
func SetupFacebook(r *floki.Floki, store UserStore, options OauthOptions) {
	var oauthCfg = &oauth.Config{
		ClientId:     options.AppId,
		ClientSecret: options.AppSecret,

		//For Google's oauth2 authentication, use this defined URL
		AuthURL: "https://www.facebook.com/dialog/oauth",

		//For Google's oauth2 authentication, use this defined URL
		TokenURL: "https://graph.facebook.com/oauth/access_token",

		//To return your oauth2 code, Google will redirect the browser to this page that you have defined
		//TODO: This exact URL should also be added in your Google API console for this project within "API Access"->"Redirect URIs"
		RedirectURL: options.RedirectURL,

		//This is the 'scope' of the data that you are asking the user's permission to access. For getting user's info, this is the url that Google has defined.
		Scope: "email",
	}

	Login := func(c *floki.Context) {
		url := oauthCfg.AuthCodeURL("")
		c.Redirect(url)
	}

	HandleOauth2Callback := func(c *floki.Context) {
		r := c.Request

		//Get the code from the response
		code := r.FormValue("code")

		t := &oauth.Transport{Config: oauthCfg}

		// Exchange the received code for a token
		tok, err := t.Exchange(code)
		if err != nil {
			log.Println(err)
			c.Redirect("/")
			return
		}

		//now get user data based on the Transport which has the token
		resp, _ := t.Client().Get("https://graph.facebook.com/me?access_token=" +
			url.QueryEscape(tok.AccessToken))

		buf := make([]byte, 1024)
		responseLen, _ := resp.Body.Read(buf)

		buf = buf[:responseLen]

		response := FacebookResponse{}
		err = json.Unmarshal(buf, &response)
		if err != nil {
			log.Println("Error unmarshalling:", err)
		}

		user := store.FindByName(response.GetId())
		if user == nil || user.GetName() == "" {
			response.Picture = getProfilePicture(response.Id)
			user = store.Create(response)
		}

		SetUser(c, user)
		c.Redirect("/")
	}

	r.GET("/loginFB", Login)
	r.GET("/oauth2/fb", HandleOauth2Callback)
}

func getProfilePicture(id string) string {
	req, err := http.NewRequest(
		"GET",
		"https://graph.facebook.com/"+id+"/picture",
		nil)
	if err != nil {
		log.Println("Error requesting Facebook picture:", err)
	}

	tr := &http.Transport{}
	resp, err := tr.RoundTrip(req)
	picture := resp.Header.Get("Location")
	resp.Body.Close()

	return picture
}

func (r FacebookResponse) GetId() string {
	return "o:fb:" + r.Id
}

func (r FacebookResponse) GetFirstName() string {
	return r.FirstName
}

func (r FacebookResponse) GetLastName() string {
	return r.LastName
}

func (r FacebookResponse) GetPicture() string {
	return r.Picture
}

func (r FacebookResponse) GetGender() string {
	return r.Gender
}

func (r FacebookResponse) GetLink() string {
	return r.Link
}

func (r FacebookResponse) GetEmail() string {
	return r.Email
}
