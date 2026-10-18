package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

const (
	passwordSMSCodeKeyPrefix     = "sms:password:code:"
	passwordSMSCooldownKeyPrefix = "sms:password:cool:"
	passwordSMSHourKeyPrefix     = "sms:password:hour:"
	passwordSMSDayKeyPrefix      = "sms:password:day:"
	passwordSMSHourLimit         = 5
	passwordSMSDayLimit          = 10
)

var (
	ErrSMSVerificationRejected = errors.New("Verification code is incorrect or has expired")
	ErrSMSVerificationLocked   = errors.New("Too many verification attempts. Please request a new code.")
	ErrSMSSendFailed           = errors.New("Failed to send verification code")

	deliverPasswordSMS = SendAliyunLoginCode
	passwordSMSMemory  = newPasswordSMSStore()
)

// SetPasswordSMSDelivererForTest replaces the SMS sender and returns a restore function.
func SetPasswordSMSDelivererForTest(deliver func(context.Context, string, string) error) func() {
	previous := deliverPasswordSMS
	deliverPasswordSMS = deliver
	return func() { deliverPasswordSMS = previous }
}

// ResetPasswordSMSMemoryForTest clears codes issued for password setup.
func ResetPasswordSMSMemoryForTest() {
	passwordSMSMemory.reset()
}

func userPhoneNumber(user *model.User) string {
	if user == nil || user.Phone == nil {
		return ""
	}
	return *user.Phone
}

// SendPasswordSetSMS texts a one-time code to the signed-in user's bound phone.
// The number is taken from the account, never from the request.
func SendPasswordSetSMS(ctx context.Context, identity AuthIdentity) (string, int, error) {
	if _, err := RequireVerificationMethod(identity, VerificationScopePasswordSet, VerificationMethodSMS); err != nil {
		return "", 0, err
	}
	user, err := model.GetUserById(identity.UserID, false)
	if err != nil {
		return "", 0, err
	}
	phone, err := NormalizeLoginPhone(userPhoneNumber(user))
	if err != nil {
		return "", 0, ErrVerificationUnavailable
	}
	// Password setup has its own send budget. Reusing the login cooldown would
	// block a code for up to a minute after the user just signed in by SMS.
	if err := reservePasswordSMSSend(identity.UserID); err != nil {
		return "", 0, err
	}
	code, err := RandomSMSLoginCode()
	if err != nil {
		releasePasswordSMSCooldown(identity.UserID)
		return "", 0, ErrSMSSendFailed
	}
	if err := savePasswordSMSCode(identity.UserID, phone, code); err != nil {
		releasePasswordSMSCooldown(identity.UserID)
		common.SysLog(common.LogText("password sms store failed for %s: %s", MaskLoginPhone(phone), err.Error()))
		return "", 0, ErrSMSSendFailed
	}
	if err := deliverPasswordSMS(ctx, phone, code); err != nil {
		deletePasswordSMSCode(identity.UserID)
		releasePasswordSMSCooldown(identity.UserID)
		common.SysLog(common.LogText("password sms send failed for %s: %s", MaskLoginPhone(phone), err.Error()))
		return "", 0, ErrSMSSendFailed
	}
	return MaskLoginPhone(phone), int(smsLoginCooldown / time.Second), nil
}

func consumePasswordSetSMS(userID int, code string) (SMSCodeStatus, error) {
	user, err := model.GetUserById(userID, false)
	if err != nil {
		return SMSCodeMismatch, err
	}
	phone, err := NormalizeLoginPhone(userPhoneNumber(user))
	if err != nil {
		return SMSCodeMismatch, ErrVerificationUnavailable
	}
	return consumePasswordSMSCode(userID, phone, code)
}

func passwordSMSKey(userID int) string {
	return passwordSMSCodeKeyPrefix + strconv.Itoa(userID)
}

func reservePasswordSMSSend(userID int) error {
	if userID <= 0 {
		return ErrVerificationUnavailable
	}
	if common.RedisEnabled {
		return reservePasswordSMSSendRedis(userID)
	}
	return passwordSMSMemory.reserve(userID, time.Now())
}

func releasePasswordSMSCooldown(userID int) {
	if common.RedisEnabled {
		_ = common.RDB.Del(context.Background(), passwordSMSCooldownKeyPrefix+strconv.Itoa(userID)).Err()
		return
	}
	passwordSMSMemory.release(userID)
}

const passwordSMSReserveScript = `
local function take(key, limit, windowMs)
  local n = redis.call('INCR', key)
  if n == 1 then
    redis.call('PEXPIRE', key, windowMs)
  end
  local ttl = redis.call('PTTL', key)
  if ttl < 1 then
    redis.call('PEXPIRE', key, windowMs)
    ttl = tonumber(windowMs)
  end
  if n > tonumber(limit) then
    return ttl
  end
  return 0
end

local coolTTL = redis.call('PTTL', KEYS[1])
if coolTTL > 0 then
  return {0, coolTTL}
end
local hourTTL = take(KEYS[2], ARGV[2], ARGV[3])
local dayTTL = take(KEYS[3], ARGV[4], ARGV[5])
if hourTTL > 0 or dayTTL > 0 then
  redis.call('DECR', KEYS[2])
  redis.call('DECR', KEYS[3])
  local retry = hourTTL
  if dayTTL > 0 and (retry == 0 or dayTTL < retry) then
    retry = dayTTL
  end
  if retry < 1 then
    retry = 1000
  end
  return {0, retry}
end
local ok = redis.call('SET', KEYS[1], '1', 'PX', ARGV[1], 'NX')
if not ok then
  redis.call('DECR', KEYS[2])
  redis.call('DECR', KEYS[3])
  local ttl = redis.call('PTTL', KEYS[1])
  if ttl < 1 then
    ttl = 1000
  end
  return {0, ttl}
end
return {1, 0}
`

func reservePasswordSMSSendRedis(userID int) error {
	id := strconv.Itoa(userID)
	values, err := common.RDB.Eval(
		context.Background(),
		passwordSMSReserveScript,
		[]string{
			passwordSMSCooldownKeyPrefix + id,
			passwordSMSHourKeyPrefix + id,
			passwordSMSDayKeyPrefix + id,
		},
		smsLoginCooldown.Milliseconds(),
		passwordSMSHourLimit,
		time.Hour.Milliseconds(),
		passwordSMSDayLimit,
		(24 * time.Hour).Milliseconds(),
	).Slice()
	if err != nil {
		return err
	}
	return smsLimitResult(values)
}

func savePasswordSMSCode(userID int, phone, code string) error {
	if common.RedisEnabled {
		return common.RDB.Set(context.Background(), passwordSMSKey(userID), phone+":"+code+":0", smsLoginCodeTTL).Err()
	}
	passwordSMSMemory.save(userID, phone, code, time.Now())
	return nil
}

func deletePasswordSMSCode(userID int) {
	if common.RedisEnabled {
		_ = common.RDB.Del(context.Background(), passwordSMSKey(userID)).Err()
		return
	}
	passwordSMSMemory.delete(userID)
}

func consumePasswordSMSCode(userID int, phone, code string) (SMSCodeStatus, error) {
	if common.RedisEnabled {
		return consumePasswordSMSCodeRedis(userID, phone, code)
	}
	return passwordSMSMemory.consume(userID, phone, code, time.Now()), nil
}

func consumePasswordSMSCodeRedis(userID int, phone, code string) (SMSCodeStatus, error) {
	const script = `
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 0
end
local phone, stored, attempts = string.match(raw, '^(%d+):(%d+):(%d+)$')
if not phone or phone ~= ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 0
end
if stored == ARGV[2] then
  redis.call('DEL', KEYS[1])
  return 1
end
attempts = tonumber(attempts) + 1
if attempts >= tonumber(ARGV[3]) then
  redis.call('DEL', KEYS[1])
  return 2
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1 then
  ttl = tonumber(ARGV[4])
end
redis.call('SET', KEYS[1], phone .. ':' .. stored .. ':' .. attempts, 'PX', ttl)
return 3
`
	result, err := common.RDB.Eval(
		context.Background(),
		script,
		[]string{passwordSMSKey(userID)},
		phone,
		code,
		smsLoginMaxAttempts,
		smsLoginCodeTTL.Milliseconds(),
	).Int()
	if err != nil {
		return SMSCodeMismatch, err
	}
	switch result {
	case 1:
		return SMSCodeAccepted, nil
	case 2:
		return SMSCodeLocked, nil
	default:
		return SMSCodeMismatch, nil
	}
}

type passwordSMSEntry struct {
	phone    string
	code     string
	attempts int
	expires  time.Time
}

type passwordSMSStore struct {
	mu       sync.Mutex
	codes    map[int]passwordSMSEntry
	cooldown map[string]time.Time
	windows  map[string]smsCounter
}

func newPasswordSMSStore() *passwordSMSStore {
	return &passwordSMSStore{
		codes:    map[int]passwordSMSEntry{},
		cooldown: map[string]time.Time{},
		windows:  map[string]smsCounter{},
	}
}

func (store *passwordSMSStore) reset() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.codes = map[int]passwordSMSEntry{}
	store.cooldown = map[string]time.Time{}
	store.windows = map[string]smsCounter{}
}

func (store *passwordSMSStore) reserve(userID int, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := strconv.Itoa(userID)
	if until, ok := store.cooldown[key]; ok && until.After(now) {
		return &SMSLoginLimit{RetryAfterSeconds: secondsCeil(until.Sub(now))}
	}
	windows := []struct {
		key    string
		limit  int
		window time.Duration
	}{
		{"h:" + key, passwordSMSHourLimit, time.Hour},
		{"d:" + key, passwordSMSDayLimit, 24 * time.Hour},
	}
	for _, window := range windows {
		if retry := counterRetry(store.windows, window.key, window.limit, now); retry > 0 {
			return &SMSLoginLimit{RetryAfterSeconds: retry}
		}
	}
	store.cooldown[key] = now.Add(smsLoginCooldown)
	for _, window := range windows {
		incrementCounter(store.windows, window.key, now, window.window)
	}
	return nil
}

func (store *passwordSMSStore) release(userID int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.cooldown, strconv.Itoa(userID))
}

func (store *passwordSMSStore) save(userID int, phone, code string, now time.Time) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.codes[userID] = passwordSMSEntry{phone: phone, code: code, expires: now.Add(smsLoginCodeTTL)}
}

func (store *passwordSMSStore) delete(userID int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.codes, userID)
}

func (store *passwordSMSStore) consume(userID int, phone, code string, now time.Time) SMSCodeStatus {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.codes[userID]
	if !ok || !entry.expires.After(now) || entry.phone != phone {
		delete(store.codes, userID)
		return SMSCodeMismatch
	}
	matched := len(code) == len(entry.code) && subtle.ConstantTimeCompare([]byte(entry.code), []byte(code)) == 1
	if matched {
		delete(store.codes, userID)
		return SMSCodeAccepted
	}
	entry.attempts++
	if entry.attempts >= smsLoginMaxAttempts {
		delete(store.codes, userID)
		return SMSCodeLocked
	}
	store.codes[userID] = entry
	return SMSCodeMismatch
}
