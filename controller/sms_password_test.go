package controller

import (
	"context"
	"net/http"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordSetUsesSMSForPhoneAccount(t *testing.T) {
	user, identity := setupSecurityEnrollmentTest(t)
	phone := "13800138000"
	require.NoError(t, model.DB.Model(user).Updates(map[string]any{"password": "", "phone": phone}).Error)
	previousSMS := common.AliyunSMS
	common.AliyunSMS = common.AliyunSMSConfig{
		AccessKeyID:     "test-key",
		AccessKeySecret: "test-secret",
		SignName:        "test-sign",
		TemplateCode:    "SMS_000000",
		Endpoint:        "https://sms.example.com",
	}
	service.ResetSMSLoginMemoryForTest()
	service.ResetPasswordSMSMemoryForTest()
	sent := ""
	restoreDeliverer := service.SetPasswordSMSDelivererForTest(func(_ context.Context, gotPhone, code string) error {
		assert.Equal(t, phone, gotPhone)
		sent = code
		return nil
	})
	t.Cleanup(func() {
		common.AliyunSMS = previousSMS
		restoreDeliverer()
		service.ResetSMSLoginMemoryForTest()
		service.ResetPasswordSMSMemoryForTest()
	})

	response := securityEnrollmentRequest(http.MethodGet, "/api/verify/methods?scope=account.password.set", "", "", identity, GetVerificationMethods)
	var methods securityEnrollmentResponse
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &methods))
	require.True(t, methods.Success, response.Body.String())
	assert.Contains(t, string(methods.Data), `"method":"sms"`)
	assert.Contains(t, string(methods.Data), `"phone":"138****8000"`)
	assert.NotContains(t, string(methods.Data), phone)
	assert.NotContains(t, string(methods.Data), `"method":"oauth"`)

	response = securityEnrollmentRequest(http.MethodPost, "/api/verify/sms/send", "", "", identity, SendPasswordSetSMS)
	var sentBody securityEnrollmentResponse
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &sentBody))
	require.True(t, sentBody.Success, response.Body.String())
	require.Len(t, sent, 6)
	assert.NotContains(t, response.Body.String(), sent)

	wrong := "000000"
	if sent == wrong {
		wrong = "111111"
	}
	response = securityEnrollmentRequest(http.MethodPost, "/api/verify", `{"method":"sms","scope":"account.password.set","code":"`+wrong+`"}`, "", identity, UniversalVerify)
	assert.Contains(t, response.Body.String(), "SMS_CODE_INVALID")

	response = securityEnrollmentRequest(http.MethodPost, "/api/verify", `{"method":"sms","scope":"account.password.set","code":"`+sent+`"}`, "", identity, UniversalVerify)
	var proof securityEnrollmentResponse
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &proof))
	require.True(t, proof.Success, response.Body.String())
	assert.Contains(t, string(proof.Data), `"method":"sms"`)
	assert.Contains(t, string(proof.Data), `"scope":"account.password.set"`)

	response = securityEnrollmentRequest(http.MethodPost, "/api/verify", `{"method":"sms","scope":"account.password.set","code":"`+sent+`"}`, "", identity, UniversalVerify)
	assert.Contains(t, response.Body.String(), "SMS_CODE_INVALID")

	response = securityEnrollmentRequest(http.MethodPost, "/api/verify", `{"method":"sms","scope":"account.delete","code":"`+sent+`"}`, "", identity, UniversalVerify)
	assert.Contains(t, response.Body.String(), "SECURITY_PROOF_METHOD_MISMATCH")
}

func TestPasswordSetSMSUnavailableWithoutConfiguration(t *testing.T) {
	user, identity := setupSecurityEnrollmentTest(t)
	require.NoError(t, model.DB.Model(user).Updates(map[string]any{"password": "", "phone": "13800138000"}).Error)
	previousSMS := common.AliyunSMS
	common.AliyunSMS = common.AliyunSMSConfig{}
	t.Cleanup(func() { common.AliyunSMS = previousSMS })

	response := securityEnrollmentRequest(http.MethodGet, "/api/verify/methods?scope=account.password.set", "", "", identity, GetVerificationMethods)
	assert.Contains(t, response.Body.String(), "SMS verification is not configured.")
	assert.NotContains(t, response.Body.String(), "13800138000")
}
