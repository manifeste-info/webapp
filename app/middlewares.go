package app

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manifeste-info/webapp/auth"
	"github.com/manifeste-info/webapp/config"
	"github.com/manifeste-info/webapp/users"
)

// authRequired is a middleware that checks if a user is authentified or not
func authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionToken, err := c.Cookie(config.SessionCookieName)
		if err == nil && auth.IsAuthenticated(sessionToken) {
			c.Next()
			return
		}
		c.Abort()

		type page struct {
			Error  bool
			ErrMsg string
		}
		c.HTML(http.StatusUnauthorized, "account.html", page{
			Error:  true,
			ErrMsg: "Tu dois être connecté·e pour accéder à cette page.",
		})
	}
}

// adminRequired is a middleware that checks if a user is an admin or not
func adminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionToken, err := c.Cookie(config.SessionCookieName)
		if err == nil && auth.IsAuthenticated(sessionToken) {
			uid, err := users.GetUserID(sessionToken)
			if err != nil {
				c.Abort()
				return
			}
			isAdmin, err := users.IsAdmin(uid)
			if err != nil {
				c.Abort()
				return
			}
			if isAdmin {
				c.Next()
				return
			}
		}

		c.Abort()
		type page struct {
			IsAdmin bool
		}
		p := page{
			IsAdmin: false,
		}
		c.HTML(http.StatusForbidden, "admin.html", p)
	}
}
