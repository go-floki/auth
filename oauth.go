package auth

import (
	"github.com/go-floki/floki"
)

type (
	OauthOptions struct {
		AppId       string
		AppSecret   string
		RedirectURL string
	}

	OauthProfile interface {
		GetId() string
		GetFirstName() string
		GetLastName() string
		GetPicture() string
		GetGender() string
		GetLink() string
		GetEmail() string
	}
)

func ParseOauthConfig(config floki.ConfigMap, key string) OauthOptions {
	opts := config.Map(key)
	return OauthOptions{
		opts.Str("appId", ""),
		opts.Str("appSecret", ""),
		opts.Str("redirectURL", ""),
	}
}
