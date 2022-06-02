package app

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manifeste-info/webapp/auth"
	"github.com/manifeste-info/webapp/users"
	log "github.com/sirupsen/logrus"
)

// authRequired is a middleware that checks if a user is authentified or not
func authRequired(a App) gin.HandlerFunc {
	return func(c *gin.Context) {
		type page struct {
			Error  bool
			ErrMsg string
		}

		token, err := c.Cookie("token")
		if err != nil {
			c.Abort()
			if err == http.ErrNoCookie {
				c.HTML(http.StatusUnauthorized, "account.html", page{
					Error:  true,
					ErrMsg: "Tu dois être connecté·e pour accéder à cette page.",
				})
				return
			}
			c.HTML(http.StatusUnauthorized, "account.html", page{
				Error:  true,
				ErrMsg: "Une erreur est survenue.",
			})
			log.Errorf("cannot get JWT from cookie token in authRequired middleware: %s", err)
			return
		}
		ok, err := auth.VerifyJWT(token, a.JWTSecret)
		if err != nil {
			c.Abort()
			c.HTML(http.StatusUnauthorized, "account.html", page{
				Error:  true,
				ErrMsg: "Une erreur est survenue.",
			})
			log.Errorf("cannot verify JWT in authRequired middleware: %s", err)
			return
		}
		if !ok {
			c.Abort()
			c.HTML(http.StatusUnauthorized, "account.html", page{
				Error:  true,
				ErrMsg: "Tu dois être connecté·e pour accéder à cette page.",
			})
			return
		}
		c.Next()
	}
}

// adminRequired is a middleware that checks if a user is an admin or not
func adminRequired(a App) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("token")
		if err != nil {
			c.Abort()
			type page struct {
				IsAdmin bool
			}
			p := page{
				IsAdmin: false,
			}
			c.HTML(http.StatusForbidden, "admin.html", p)
		}
		cl, err := auth.GetJWTClaims(token, a.JWTSecret)
		if err != nil {
			c.Abort()
			type page struct {
				IsAdmin bool
			}
			p := page{
				IsAdmin: false,
			}
			c.HTML(http.StatusInternalServerError, "admin.html", p)
		}
		ok, err := users.IsAdmin(cl.UID)
		if err != nil || !ok {
			c.Abort()
			type page struct {
				IsAdmin bool
			}
			p := page{
				IsAdmin: false,
			}
			c.HTML(http.StatusForbidden, "admin.html", p)
		}
		c.Next()
	}

}
