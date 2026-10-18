package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/require"
)

func TestNormalizeLoginPhone(t *testing.T) {
	phone, err := NormalizeLoginPhone(" 138-0013-8000 ")
	require.NoError(t, err)
	require.Equal(t, "13800138000", phone)

	phone, err = NormalizeLoginPhone("+86 13800138000")
	require.NoError(t, err)
	require.Equal(t, "13800138000", phone)

	_, err = NormalizeLoginPhone("12345")
	require.Error(t, err)
	_, err = NormalizeLoginPhone("23800138000")
	require.Error(t, err)
}

func TestMemorySMSLoginCodeIsSingleUseAndLocks(t *testing.T) {
	previousRedis := common.RedisEnabled
	common.RedisEnabled = false
	ResetSMSLoginMemoryForTest()
	t.Cleanup(func() {
		common.RedisEnabled = previousRedis
		ResetSMSLoginMemoryForTest()
	})

	require.NoError(t, ReserveSMSLoginSend("13800138000", "192.0.2.1"))
	require.Error(t, ReserveSMSLoginSend("13800138000", "192.0.2.1"))
	ReleaseSMSLoginCooldown("13800138000")
	require.NoError(t, SaveSMSLoginCode("13800138000", "123456"))

	status, err := ConsumeSMSLoginCode("13800138000", "000000")
	require.NoError(t, err)
	require.Equal(t, SMSCodeMismatch, status)

	status, err = ConsumeSMSLoginCode("13800138000", "123456")
	require.NoError(t, err)
	require.Equal(t, SMSCodeAccepted, status)

	status, err = ConsumeSMSLoginCode("13800138000", "123456")
	require.NoError(t, err)
	require.Equal(t, SMSCodeMismatch, status)

	require.NoError(t, SaveSMSLoginCode("13800138001", "654321"))
	for range 4 {
		status, err = ConsumeSMSLoginCode("13800138001", "000000")
		require.NoError(t, err)
		require.Equal(t, SMSCodeMismatch, status)
	}
	status, err = ConsumeSMSLoginCode("13800138001", "000000")
	require.NoError(t, err)
	require.Equal(t, SMSCodeLocked, status)
	status, err = ConsumeSMSLoginCode("13800138001", "654321")
	require.NoError(t, err)
	require.Equal(t, SMSCodeMismatch, status)
}

func TestSMSLoginSendAndVerifyCaps(t *testing.T) {
	previousRedis := common.RedisEnabled
	common.RedisEnabled = false
	ResetSMSLoginMemoryForTest()
	t.Cleanup(func() {
		common.RedisEnabled = previousRedis
		ResetSMSLoginMemoryForTest()
	})

	start := time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)
	require.NoError(t, reserveSMSLoginSend("13800138000", "192.0.2.10", start))
	err := reserveSMSLoginSend("13800138000", "192.0.2.10", start.Add(time.Second))
	var limit *SMSLoginLimit
	require.ErrorAs(t, err, &limit)
	require.GreaterOrEqual(t, limit.RetryAfterSeconds, 59)

	for i := 1; i < smsLoginIPMinuteLimit; i++ {
		require.NoError(t, reserveSMSLoginSend(fmt.Sprintf("1380013%04d", i), "192.0.2.10", start))
	}
	err = reserveSMSLoginSend("13800139999", "192.0.2.10", start)
	require.ErrorAs(t, err, &limit)

	for i := 0; i < smsLoginPhoneHourLimit; i++ {
		require.NoError(t, reserveSMSLoginSend("13800138111", fmt.Sprintf("192.0.2.%d", 20+i), start.Add(time.Duration(i)*time.Minute)))
	}
	err = reserveSMSLoginSend("13800138111", "192.0.2.40", start.Add(5*time.Minute))
	require.ErrorAs(t, err, &limit)

	for i := 0; i < smsLoginVerifyPhoneLimit; i++ {
		require.NoError(t, reserveSMSLoginVerify("13800138222", "192.0.2.50", start))
	}
	err = reserveSMSLoginVerify("13800138222", "192.0.2.50", start)
	require.ErrorAs(t, err, &limit)
	require.NoError(t, reserveSMSLoginVerify("13800138223", "192.0.2.51", start))
}

func TestAliyunSMSPostsSignedSendSms(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		body = string(payload)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Code":"OK","Message":"OK"}`))
	}))
	t.Cleanup(server.Close)

	previous := common.AliyunSMS
	common.AliyunSMS = common.AliyunSMSConfig{
		AccessKeyID:     "testid",
		AccessKeySecret: "testsecret",
		SignName:        "测试签名",
		TemplateCode:    "SMS_1",
		Endpoint:        server.URL,
		RegionID:        "cn-hangzhou",
	}
	t.Cleanup(func() { common.AliyunSMS = previous })

	require.NoError(t, SendAliyunLoginCode(context.Background(), "13800138000", "123456"))
	require.Contains(t, body, "Action=SendSms")
	require.Contains(t, body, "PhoneNumbers=13800138000")
	require.Contains(t, body, "TemplateCode=SMS_1")
	require.Contains(t, body, "TemplateParam="+aliyunPercentEncode(`{"code":"123456"}`))
	require.Contains(t, body, "Signature=")
	require.NotContains(t, body, "testsecret")
	require.Contains(t, body, "SignName="+aliyunPercentEncode("测试签名"))
}

func TestAliyunSignatureGolden(t *testing.T) {
	params := map[string]string{
		"AccessKeyId":      "testid",
		"Action":           "SendSms",
		"Format":           "JSON",
		"PhoneNumbers":     "13800138000",
		"RegionId":         "cn-hangzhou",
		"SignName":         "签名",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   "nonce-1",
		"SignatureVersion": "1.0",
		"TemplateCode":     "SMS_1",
		"TemplateParam":    `{"code":"123456"}`,
		"Timestamp":        "2026-01-02T03:04:05Z",
		"Version":          "2017-05-25",
	}
	body := signedAliyunRPCBody("POST", params, "testsecret")
	signature := body[strings.LastIndex(body, "Signature=")+len("Signature="):]
	require.Equal(t, "fgVu0fGI0KYaTBaxgEV0%2BVszl%2Fs%3D", signature)
}
