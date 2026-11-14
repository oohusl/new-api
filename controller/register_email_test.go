package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestEmailLocalDisplayTruncates(t *testing.T) {
	got := emailLocalDisplay("abcdefghijklmnopqrstuvwxyz@example.com")
	if len([]rune(got)) != 20 {
		t.Fatalf("display name length = %d", len([]rune(got)))
	}
	if got != "abcdefghijklmnopqrst" {
		t.Fatalf("display name = %q", got)
	}
}

func TestEmailRegistrationUsesNormalizedEmailAsUsername(t *testing.T) {
	db := setupSMSLoginTest(t)
	passwordRegistration := common.PasswordRegisterEnabled
	emailVerification := common.EmailVerificationEnabled
	generateToken := constant.GenerateDefaultToken
	newUserQuota := common.QuotaForNewUser
	common.PasswordRegisterEnabled = true
	common.EmailVerificationEnabled = false
	constant.GenerateDefaultToken = false
	common.QuotaForNewUser = 0
	t.Cleanup(func() {
		common.PasswordRegisterEnabled = passwordRegistration
		common.EmailVerificationEnabled = emailVerification
		constant.GenerateDefaultToken = generateToken
		common.QuotaForNewUser = newUserQuota
	})

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/user/register", strings.NewReader(
		`{"username":"different","email":"  Alice.Long.Address@example.com  ","password":"test-password-123"}`,
	))
	Register(ctx)

	var response struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &response))
	require.True(t, response.Success, response.Message)

	const email = "alice.long.address@example.com"
	var user model.User
	require.NoError(t, db.First(&user, "email = ?", email).Error)
	require.Equal(t, email, user.Username)
	login := model.User{Username: email, Password: "test-password-123"}
	require.NoError(t, login.ValidateAndFill())
	require.Equal(t, user.Id, login.Id)
}
