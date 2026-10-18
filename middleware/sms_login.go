package middleware

import (
	"net/http"

	"github.com/QuantumNous/new-api/common"

	"github.com/gin-gonic/gin"
)

// SMSLoginSiteGuard rejects SMS login calls that do not come from the user site.
// The admin console shares this API process and must not be able to use the flow.
func SMSLoginSiteGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !AllowSMSLogin(c) {
			c.Abort()
			return
		}
		c.Next()
	}
}

// AllowSMSLogin reports whether this browser request may use SMS login.
// A refusal is already written to the response.
func AllowSMSLogin(c *gin.Context) bool {
	if !common.SMSLoginEnabled() {
		common.ApiErrorT(c, "SMS login is not configured")
		return false
	}
	origin, ok := requestBrowserOrigin(c.Request)
	if !ok || !common.SMSLoginOriginAllowed(origin) {
		common.ApiErrorStatus(c, http.StatusForbidden, common.NewMessage("SMS login is not available"))
		return false
	}
	return true
}
