package model

import (
	"errors"
	"fmt"

	"github.com/QuantumNous/new-api/common"

	"gorm.io/gorm"
)

var ErrSMSPhoneDeleted = errors.New("sms phone belongs to a deleted user")

// GetUserByPhone returns the user bound to phone, including a soft-deleted row.
// A missing phone returns nil, nil.
func GetUserByPhone(phone string) (*User, error) {
	if phone == "" {
		return nil, fmt.Errorf("phone is empty")
	}
	var user User
	err := DB.Unscoped().Where("phone = ?", phone).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// CreateSMSUser inserts a common user bound to a verified phone number.
// The phone becomes the username when that name is free.
func CreateSMSUser(phone string, inviterID int) (*User, error) {
	if phone == "" {
		return nil, fmt.Errorf("phone is empty")
	}
	var created *User
	err := DB.Transaction(func(tx *gorm.DB) error {
		existing, err := getUserByPhoneWithTx(tx, phone)
		if err != nil {
			return err
		}
		if existing != nil {
			if existing.DeletedAt.Valid {
				return ErrSMSPhoneDeleted
			}
			return gorm.ErrDuplicatedKey
		}
		username, err := availableSMSUsername(tx, phone)
		if err != nil {
			return err
		}
		phoneValue := phone
		user := &User{
			Username:    username,
			DisplayName: phone,
			Phone:       &phoneValue,
			Role:        common.RoleCommonUser,
			Status:      common.UserStatusEnabled,
			Group:       "default",
			AuthVersion: 1,
		}
		if err := user.InsertWithTx(tx, inviterID); err != nil {
			return err
		}
		created = user
		return nil
	})
	if err != nil {
		return nil, err
	}
	created.FinishInsert(inviterID)
	return created, nil
}

func getUserByPhoneWithTx(tx *gorm.DB, phone string) (*User, error) {
	var user User
	err := tx.Unscoped().Where("phone = ?", phone).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func availableSMSUsername(tx *gorm.DB, phone string) (string, error) {
	candidates := []string{phone, "u" + phone}
	suffix, err := common.GenerateRandomCharsKey(6)
	if err != nil {
		return "", err
	}
	candidates = append(candidates, "p"+phone[:6]+suffix)
	for _, username := range candidates {
		var count int64
		if err := tx.Unscoped().Model(&User{}).Where("username = ?", username).Count(&count).Error; err != nil {
			return "", err
		}
		if count == 0 {
			return username, nil
		}
	}
	return "", fmt.Errorf("no username available for phone user")
}
