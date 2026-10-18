package controller

import (
	"errors"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type smsCodeRequest struct {
	Phone string `json:"phone"`
}

type smsLoginRequest struct {
	Phone   string `json:"phone"`
	Code    string `json:"code"`
	AffCode string `json:"aff_code"`
}

func SendSMSLoginCode(c *gin.Context) {
	if !middleware.AllowSMSLogin(c) {
		return
	}
	var request smsCodeRequest
	if err := common.DecodeJson(c.Request.Body, &request); err != nil {
		common.ApiErrorT(c, "Invalid parameters")
		return
	}
	phone, err := service.NormalizeLoginPhone(request.Phone)
	if err != nil {
		common.ApiErrorT(c, "Please enter a valid mobile number")
		return
	}
	if err := service.ReserveSMSLoginSend(phone, c.ClientIP()); err != nil {
		var limit *service.SMSLoginLimit
		if errors.As(err, &limit) {
			seconds := limit.RetryAfterSeconds
			if seconds < 1 {
				seconds = 1
			}
			common.ApiErrorT(c, "Please wait {{seconds}} seconds before requesting another verification code.", map[string]any{"seconds": seconds})
			return
		}
		common.SysLog(common.LogText("sms login reserve failed for %s: %s", service.MaskLoginPhone(phone), err.Error()))
		common.ApiErrorT(c, "Failed to send verification code")
		return
	}
	code, err := service.RandomSMSLoginCode()
	if err != nil {
		service.ReleaseSMSLoginCooldown(phone)
		common.ApiErrorT(c, "Failed to send verification code")
		return
	}
	if err := service.SaveSMSLoginCode(phone, code); err != nil {
		service.ReleaseSMSLoginCooldown(phone)
		common.SysLog(common.LogText("sms login code store failed for %s: %s", service.MaskLoginPhone(phone), err.Error()))
		common.ApiErrorT(c, "Failed to send verification code")
		return
	}
	if err := service.SendAliyunLoginCode(c.Request.Context(), phone, code); err != nil {
		service.DeleteSMSLoginCode(phone)
		service.ReleaseSMSLoginCooldown(phone)
		common.SysLog(common.LogText("sms login send failed for %s: %s", service.MaskLoginPhone(phone), err.Error()))
		common.ApiErrorT(c, "Failed to send verification code")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
}

func SMSLogin(c *gin.Context) {
	if !middleware.AllowSMSLogin(c) {
		return
	}
	var request smsLoginRequest
	if err := common.DecodeJson(c.Request.Body, &request); err != nil {
		common.ApiErrorT(c, "Invalid parameters")
		return
	}
	phone, err := service.NormalizeLoginPhone(request.Phone)
	if err != nil {
		common.ApiErrorT(c, "Please enter a valid mobile number")
		return
	}
	code := strings.TrimSpace(request.Code)
	if len(code) != 6 {
		common.ApiErrorT(c, "Verification code is incorrect or has expired")
		return
	}
	status, err := service.ConsumeSMSLoginCode(phone, code)
	if err != nil {
		common.SysLog(common.LogText("sms login code check failed for %s: %s", service.MaskLoginPhone(phone), err.Error()))
		common.ApiErrorT(c, "Verification code is incorrect or has expired")
		return
	}
	if status == service.SMSCodeLocked {
		common.ApiErrorT(c, "Too many verification attempts. Please request a new code.")
		return
	}
	if status != service.SMSCodeAccepted {
		common.ApiErrorT(c, "Verification code is incorrect or has expired")
		return
	}

	user, err := smsLoginUser(c, phone, strings.TrimSpace(request.AffCode))
	if err != nil {
		writeSMSLoginUserError(c, err)
		return
	}
	c.Set("login_method", "sms")
	setupLogin(user, nil, c)
}

func smsLoginUser(c *gin.Context, phone, affCode string) (*model.User, error) {
	if len(affCode) > 32 {
		return nil, common.NewMessage("Invalid parameters")
	}
	existing, err := model.GetUserByPhone(phone)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if existing.DeletedAt.Valid {
			return nil, model.ErrSMSPhoneDeleted
		}
		if existing.Status != common.UserStatusEnabled {
			return nil, common.NewMessage("User has been banned")
		}
		return existing, nil
	}
	if !common.RegisterEnabled {
		return nil, common.NewMessage("New user registration has been disabled by administrator")
	}
	inviterID := 0
	if affCode != "" {
		if id, err := model.GetUserIdByAffCode(affCode); err == nil {
			inviterID = id
		}
	}
	user, err := model.CreateSMSUser(phone, inviterID)
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		existing, readErr := model.GetUserByPhone(phone)
		if readErr != nil {
			return nil, readErr
		}
		if existing == nil || existing.DeletedAt.Valid || existing.Status != common.UserStatusEnabled {
			return nil, err
		}
		return existing, nil
	}
	if err != nil {
		return nil, err
	}
	if err := createDefaultTokenForSMSUser(c, user); err != nil {
		return nil, err
	}
	return user, nil
}

func writeSMSLoginUserError(c *gin.Context, err error) {
	var message *common.Message
	if errors.As(err, &message) {
		common.ApiError(c, err)
		return
	}
	if errors.Is(err, model.ErrSMSPhoneDeleted) {
		common.ApiErrorT(c, "User has been deleted")
		return
	}
	common.SysLog(common.LogText("sms login user error: %s", err.Error()))
	common.ApiErrorT(c, "Database error, please contact the administrator")
}

func createDefaultTokenForSMSUser(c *gin.Context, user *model.User) error {
	if !constant.GenerateDefaultToken || user == nil {
		return nil
	}
	key, err := common.GenerateKey()
	if err != nil {
		return err
	}
	token := model.Token{
		UserId:             user.Id,
		Name:               i18n.T(c, i18n.MsgUserDefaultTokenName, map[string]any{"Username": user.Username}),
		Key:                key,
		CreatedTime:        common.GetTimestamp(),
		AccessedTime:       common.GetTimestamp(),
		ExpiredTime:        -1,
		RemainQuota:        500000,
		UnlimitedQuota:     true,
		ModelLimitsEnabled: false,
	}
	token.AllowUserQuotaQuery = true
	if setting.DefaultUseAutoGroup {
		token.Group = "auto"
	}
	return token.Insert()
}
