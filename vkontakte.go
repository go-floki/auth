package auth

import (
	"code.google.com/p/goauth2/oauth"
	"encoding/json"
	"github.com/go-floki/floki"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

const VK_API_METHOD_URL = "https://api.vk.com/method/"
const VK_AUTH_HOST = "https://oauth.vk.com/authorize"

type (
	VKApi struct {
		AccessToken string
		UserId      int
		ExpiresIn   int
	}

	VKAuth struct {
		AppId        string
		Scope        string
		RedirectUri  string
		ResponseType string
	}

	VKTokenResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		UserId      int    `json:"user_id"`
		Email       string `json:"email"`
	}

	VKResponse struct {
		UserInfo []VKUserInfo `json:"response"`
	}

	VKUserInfo struct {
		Id            int    `json:"uid"`
		Email         string //`json:"email"`
		VerifiedEmail bool   //`json:"verified"`
		FirstName     string `json:"first_name"`
		LastName      string `json:"last_name"`
		Link          string //`json:"link"`
		Picture       string `json:"photo_medium"`
		Gender        int    `json:"sex"`
		University    string `json:"university_name"`
		Faculty       string `json:"faculty_name"`
		Education     string `json:"education_status"`
		Birthday      string `json:"bdate"`
	}
)

//
func SetupVKontakte(r *floki.Floki, store UserStore, options OauthOptions) {
	var oauthCfg = &oauth.Config{
		ClientId:     options.AppId,
		ClientSecret: options.AppSecret,

		//For Google's oauth2 authentication, use this defined URL
		AuthURL: "https://oauth.vk.com/authorize",

		//For Google's oauth2 authentication, use this defined URL
		TokenURL: "https://oauth.vk.com/access_token",

		//To return your oauth2 code, Google will redirect the browser to this page that you have defined
		//TODO: This exact URL should also be added in your Google API console for this project within "API Access"->"Redirect URIs"
		RedirectURL: options.RedirectURL,

		//This is the 'scope' of the data that you are asking the user's permission to access. For getting user's info, this is the url that Google has defined.
		Scope: "email",
	}

	Login := func(c *floki.Context) {
		url := oauthCfg.AuthCodeURL("")
		log.Println("url:", url)
		c.Redirect(url)

	}

	HandleOauth2Callback := func(c *floki.Context) {
		//Get the code from the response
		r := c.Request
		code := r.FormValue("code")

		authUrl := "https://oauth.vk.com/access_token" +
			"?client_id=" + options.AppId +
			"&client_secret=" + options.AppSecret +
			"&code=" + code + "&redirect_uri=" + options.RedirectURL

		resp, err := http.Get(authUrl)
		if err != nil {
			c.Logger().Println("error fetching URL:", authUrl, err)
			handleError(c, err.Error())
			return
		}

		buf := make([]byte, 1024)
		responseLen, _ := resp.Body.Read(buf)
		buf = buf[:responseLen]

		token := VKTokenResponse{}
		err = json.Unmarshal(buf, &token)
		if err != nil {
			log.Println("Error unmarshalling:", err)
			handleError(c, "Invalid server response")
			return
		}

		///
		api := VKApi{
			token.AccessToken,
			token.UserId,
			token.ExpiresIn,
		}

		userInfoStr := api.VKRequest("getProfiles", map[string]string{
			"uids":   strconv.Itoa(token.UserId),
			"fields": "first_name,last_name,sex,bdate,city,country,photo_medium,education",
		})

		vkResponse := VKResponse{}
		err = json.Unmarshal([]byte(userInfoStr), &vkResponse)
		if err != nil || len(vkResponse.UserInfo) == 0 {
			log.Println("Error unmarshalling:", err)
			handleError(c, "Invalid server response")
			return
		}

		userInfo := &vkResponse.UserInfo[0]

		user := store.FindByName(userInfo.GetId())
		if user == nil || user.GetName() == "" {
			userInfo.Email = token.Email
			user = store.Create(userInfo)
		}

		SetUser(c, user)
		c.Redirect("/")
	}

	r.GET("/loginVK", Login)
	r.GET("/oauth2/vk", HandleOauth2Callback)
}

func (r VKUserInfo) GetId() string {
	return "o:vk:" + strconv.Itoa(r.Id)
}

func (r VKUserInfo) GetFirstName() string {
	return r.FirstName
}

func (r VKUserInfo) GetLastName() string {
	return r.LastName
}

func (r VKUserInfo) GetPicture() string {
	return r.Picture
}

func (r VKUserInfo) GetGender() string {
	switch r.Gender {
	case 1:
		return "female"
	case 2:
		return "male"
	default:
		return "-"
	}
}

func (r VKUserInfo) GetLink() string {
	return r.Link
}

func (r VKUserInfo) GetEmail() string {
	return r.Email
}

func handleError(c *floki.Context, errorMsg string) {
	c.Redirect("/login?error=" + url.QueryEscape(errorMsg))
}

func (vk VKApi) VKRequest(methodName string, params map[string]string) string {
	u, err := url.Parse(VK_API_METHOD_URL + methodName)
	if err != nil {
		panic(err)
	}

	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	q.Set("access_token", vk.AccessToken)
	u.RawQuery = q.Encode()

	resp, err := http.Get(u.String())
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	return string(content)
}

func (a VKAuth) GetAuthUrl() string {
	u, err := url.Parse(VK_AUTH_HOST)
	if err != nil {
		panic(err)
	}

	q := u.Query()
	q.Set("client_id", a.AppId)
	q.Set("scope", a.Scope)
	q.Set("redirect_uri", a.RedirectUri)
	q.Set("response_type", a.ResponseType)
	u.RawQuery = q.Encode()

	return u.String()
}
