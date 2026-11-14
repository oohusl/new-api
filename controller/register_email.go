package controller

import (
	"strings"

	"github.com/QuantumNous/new-api/model"
)

func emailLocalDisplay(email string) string {
	local := email
	if at := strings.IndexByte(email, '@'); at >= 0 {
		local = email[:at]
	}
	local = strings.TrimSpace(local)
	if local == "" {
		return "user"
	}
	runes := []rune(local)
	if len(runes) > model.UserNameMaxLength {
		runes = runes[:model.UserNameMaxLength]
	}
	return string(runes)
}
