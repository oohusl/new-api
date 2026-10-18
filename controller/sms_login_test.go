package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestSMSLoginRegistersThenSignsInExistingUser(t *testing.T) {
	db := setupSMSLoginTest(t)
	gin.SetMode(gin.TestMode)
	require.NoError(t, service.SaveSMSLoginCode("13800138000", "123456"))

	recorder := postSMSLogin(t, `{"phone":"13800138000","code":"123456","aff_code":""}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	var created struct {
		Success bool `json:"success"`
		Data    struct {
			AccessToken string `json:"access_token"`
			User        struct {
				Username string `json:"username"`
				Phone    string `json:"phone"`
				Role     int    `json:"role"`
			} `json:"user"`
		} `json:"data"`
	}
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &created))
	require.True(t, created.Success)
	require.NotEmpty(t, created.Data.AccessToken)
	require.Equal(t, "13800138000", created.Data.User.Username)
	require.Equal(t, "13800138000", created.Data.User.Phone)
	require.Equal(t, common.RoleCommonUser, created.Data.User.Role)

	var count int64
	require.NoError(t, db.Model(&model.User{}).Count(&count).Error)
	require.Equal(t, int64(1), count)

	service.ResetSMSLoginMemoryForTest()
	require.NoError(t, service.SaveSMSLoginCode("13800138000", "654321"))
	again := postSMSLogin(t, `{"phone":"138 0013 8000","code":"654321"}`)
	require.Equal(t, http.StatusOK, again.Code)
	require.NoError(t, db.Model(&model.User{}).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

func TestSMSLoginRejectsUnknownCodeAndDeletedPhone(t *testing.T) {
	db := setupSMSLoginTest(t)
	gin.SetMode(gin.TestMode)
	require.NoError(t, service.SaveSMSLoginCode("13800138000", "123456"))

	wrong := postSMSLogin(t, `{"phone":"13800138000","code":"000000"}`)
	require.Equal(t, http.StatusOK, wrong.Code)
	require.Contains(t, wrong.Body.String(), "Verification code is incorrect or has expired")
	var count int64
	require.NoError(t, db.Model(&model.User{}).Count(&count).Error)
	require.Zero(t, count)

	user := &model.User{
		Username: "gone-user", DisplayName: "gone", Password: "unused-password",
		Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1,
	}
	phone := "13900139000"
	user.Phone = &phone
	require.NoError(t, db.Create(user).Error)
	require.NoError(t, db.Delete(user).Error)
	service.ResetSMSLoginMemoryForTest()
	require.NoError(t, service.SaveSMSLoginCode(phone, "123456"))
	deleted := postSMSLogin(t, `{"phone":"13900139000","code":"123456"}`)
	require.Contains(t, deleted.Body.String(), "User has been deleted")
	require.NoError(t, db.Model(&model.User{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestSMSLoginVerifyRateLimitCountsMalformedCodes(t *testing.T) {
	setupSMSLoginTest(t)
	gin.SetMode(gin.TestMode)
	blocked := false
	for range 15 {
		recorder := postSMSLogin(t, `{"phone":"13800138000","code":"1"}`)
		if strings.Contains(recorder.Body.String(), "Please wait") {
			blocked = true
			break
		}
		require.Contains(t, recorder.Body.String(), "Verification code is incorrect or has expired")
	}
	require.True(t, blocked)
}

func TestSMSLoginRejectsAdminOrigin(t *testing.T) {
	setupSMSLoginTest(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/user/login/sms", bytes.NewBufferString(`{"phone":"13800138000","code":"123456"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("Origin", "https://www.chroneb.cn:8443")
	c.Request.RemoteAddr = "192.0.2.8:1234"
	SMSLogin(c)
	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.Contains(t, recorder.Body.String(), "SMS login is not available")
}

func setupSMSLoginTest(t *testing.T) *gorm.DB {
	t.Helper()
	previousDB := model.DB
	previousRedis := common.RedisEnabled
	previousRegister := common.RegisterEnabled
	previousOrigins := append([]string(nil), common.SMSLoginAllowedOrigins...)
	previousAliyun := common.AliyunSMS
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.TwoFA{}, &model.PasskeyCredential{}, &model.Token{}))
	model.DB = db
	common.RedisEnabled = false
	common.RegisterEnabled = true
	require.NoError(t, common.LoadSMSLoginSettings("https://www.chroneb.cn", common.AliyunSMSConfig{
		AccessKeyID: "testid", AccessKeySecret: "testsecret", SignName: "签名", TemplateCode: "SMS_1",
		Endpoint: "https://dysmsapi.aliyuncs.com", RegionID: "cn-hangzhou",
	}))
	service.ResetSMSLoginMemoryForTest()
	t.Cleanup(func() {
		model.DB = previousDB
		common.RedisEnabled = previousRedis
		common.RegisterEnabled = previousRegister
		common.SMSLoginAllowedOrigins = previousOrigins
		common.AliyunSMS = previousAliyun
		service.ResetSMSLoginMemoryForTest()
	})
	return db
}

func postSMSLogin(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/user/login/sms", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("Origin", "https://www.chroneb.cn")
	c.Request.RemoteAddr = "192.0.2.8:1234"
	SMSLogin(c)
	return recorder
}
