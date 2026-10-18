package common

import (
	"crypto/subtle"
	"fmt"
	"os"
	"strings"
)

// AliyunSMSConfig is the Alibaba Cloud Dysmsapi credential set for login codes.
// Empty credentials leave SMS login disabled.
type AliyunSMSConfig struct {
	AccessKeyID     string
	AccessKeySecret string
	SignName        string
	TemplateCode    string
	Endpoint        string
	RegionID        string
}

func (config AliyunSMSConfig) Configured() bool {
	return config.AccessKeyID != "" &&
		config.AccessKeySecret != "" &&
		config.SignName != "" &&
		config.TemplateCode != "" &&
		config.Endpoint != ""
}

var (
	// SMSLoginAllowedOrigins are exact browser origins that may call SMS login.
	// The admin console origin must not be included.
	SMSLoginAllowedOrigins []string
	AliyunSMS              AliyunSMSConfig
)

// SMSLoginEnabled reports whether SMS login can accept user-site requests.
func SMSLoginEnabled() bool {
	return len(SMSLoginAllowedOrigins) > 0 && AliyunSMS.Configured()
}

// InitSMSLoginSettings loads SMS login from the environment.
// An empty origin list disables the feature. A malformed origin fails startup.
func InitSMSLoginSettings() error {
	endpoint := strings.TrimSpace(os.Getenv("ALIYUN_SMS_ENDPOINT"))
	if endpoint == "" {
		endpoint = "https://dysmsapi.aliyuncs.com"
	}
	regionID := strings.TrimSpace(os.Getenv("ALIYUN_SMS_REGION_ID"))
	if regionID == "" {
		regionID = "cn-hangzhou"
	}
	if err := LoadSMSLoginSettings(os.Getenv("SMS_LOGIN_ALLOWED_ORIGINS"), AliyunSMSConfig{
		AccessKeyID:     strings.TrimSpace(os.Getenv("ALIYUN_SMS_ACCESS_KEY_ID")),
		AccessKeySecret: strings.TrimSpace(os.Getenv("ALIYUN_SMS_ACCESS_KEY_SECRET")),
		SignName:        strings.TrimSpace(os.Getenv("ALIYUN_SMS_SIGN_NAME")),
		TemplateCode:    strings.TrimSpace(os.Getenv("ALIYUN_SMS_TEMPLATE_CODE")),
		Endpoint:        endpoint,
		RegionID:        regionID,
	}); err != nil {
		return err
	}
	switch {
	case SMSLoginEnabled():
		SysLog(LogText("SMS login enabled for %d user-site origins", len(SMSLoginAllowedOrigins)))
	case len(SMSLoginAllowedOrigins) > 0 || aliyunSMSPartiallyConfigured(AliyunSMS):
		SysLog(LogText("SMS login is disabled because Aliyun SMS settings or SMS_LOGIN_ALLOWED_ORIGINS are incomplete"))
	}
	return nil
}

func aliyunSMSPartiallyConfigured(config AliyunSMSConfig) bool {
	return config.AccessKeyID != "" || config.AccessKeySecret != "" || config.SignName != "" || config.TemplateCode != ""
}

// LoadSMSLoginSettings replaces the in-memory SMS login configuration.
func LoadSMSLoginSettings(originsRaw string, config AliyunSMSConfig) error {
	origins, err := parseSMSLoginOrigins(originsRaw)
	if err != nil {
		return err
	}
	SMSLoginAllowedOrigins = origins
	AliyunSMS = config
	return nil
}

func parseSMSLoginOrigins(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var origins []string
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("SMS_LOGIN_ALLOWED_ORIGINS contains an empty origin")
		}
		origin, err := NormalizeOrigin(part)
		if err != nil {
			return nil, fmt.Errorf("invalid SMS_LOGIN_ALLOWED_ORIGINS: %w", err)
		}
		origins = append(origins, origin)
	}
	return origins, nil
}

// SMSLoginOriginAllowed reports whether origin is an exact user-site origin.
func SMSLoginOriginAllowed(origin string) bool {
	for _, allowed := range SMSLoginAllowedOrigins {
		if subtle.ConstantTimeCompare([]byte(origin), []byte(allowed)) == 1 {
			return true
		}
	}
	return false
}
