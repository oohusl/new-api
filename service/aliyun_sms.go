package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/google/uuid"
)

const aliyunSMSVersion = "2017-05-25"

type aliyunSMSResponse struct {
	Code      string `json:"Code"`
	Message   string `json:"Message"`
	RequestID string `json:"RequestId"`
}

// SendAliyunLoginCode sends a login verification code through Alibaba Cloud SMS.
func SendAliyunLoginCode(ctx context.Context, phone, code string) error {
	config := common.AliyunSMS
	if !config.Configured() {
		return fmt.Errorf("aliyun sms is not configured")
	}
	params := map[string]string{
		"AccessKeyId":      config.AccessKeyID,
		"Action":           "SendSms",
		"Format":           "JSON",
		"PhoneNumbers":     phone,
		"RegionId":         config.RegionID,
		"SignName":         config.SignName,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   uuid.NewString(),
		"SignatureVersion": "1.0",
		"TemplateCode":     config.TemplateCode,
		"TemplateParam":    fmt.Sprintf(`{"code":"%s"}`, code),
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          aliyunSMSVersion,
	}
	body := signedAliyunRPCBody("POST", params, config.AccessKeySecret)
	endpoint := strings.TrimRight(config.Endpoint, "/") + "/"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("aliyun sms http %d", response.StatusCode)
	}
	var result aliyunSMSResponse
	if err := json.Unmarshal(payload, &result); err != nil {
		return err
	}
	if result.Code != "OK" {
		return fmt.Errorf("aliyun sms %s: %s", result.Code, result.Message)
	}
	return nil
}

func signedAliyunRPCBody(method string, params map[string]string, accessKeySecret string) string {
	canonical := canonicalAliyunQuery(params)
	stringToSign := method + "&" + aliyunPercentEncode("/") + "&" + aliyunPercentEncode(canonical)
	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	_, _ = mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return canonical + "&Signature=" + aliyunPercentEncode(signature)
}

func canonicalAliyunQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, aliyunPercentEncode(key)+"="+aliyunPercentEncode(params[key]))
	}
	return strings.Join(parts, "&")
}

func aliyunPercentEncode(value string) string {
	encoded := url.QueryEscape(value)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	return encoded
}
