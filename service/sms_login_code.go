package service

import (
	"context"
	crand "crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
)

const (
	smsLoginCodeTTL           = 5 * time.Minute
	smsLoginCooldown          = 60 * time.Second
	smsLoginPhoneHourWindow   = time.Hour
	smsLoginDailyWindow       = 24 * time.Hour
	smsLoginIPMinuteWindow    = time.Minute
	smsLoginIPWindow          = time.Hour
	smsLoginIPDayWindow       = 24 * time.Hour
	smsLoginGlobalWindow      = time.Minute
	smsLoginVerifyWindow      = 10 * time.Minute
	smsLoginCodeDigits        = 6
	smsLoginMaxAttempts       = 5
	smsLoginPhoneHourLimit    = 5
	smsLoginDailyPhoneLimit   = 10
	smsLoginIPMinuteLimit     = 5
	smsLoginHourlyIPLimit     = 20
	smsLoginIPDayLimit        = 50
	smsLoginGlobalMinuteLimit = 20
	smsLoginVerifyPhoneLimit  = 10
	smsLoginVerifyIPLimit     = 40

	smsLoginCodeKeyPrefix      = "sms:login:code:"
	smsLoginCooldownKeyPrefix  = "sms:login:cool:"
	smsLoginPhoneHourKeyPrefix = "sms:login:ph:"
	smsLoginDailyKeyPrefix     = "sms:login:day:"
	smsLoginIPMinuteKeyPrefix  = "sms:login:ipm:"
	smsLoginIPKeyPrefix        = "sms:login:ip:"
	smsLoginIPDayKeyPrefix     = "sms:login:ipd:"
	smsLoginGlobalKey          = "sms:login:global"
	smsLoginVerifyPhonePrefix  = "sms:login:vphone:"
	smsLoginVerifyIPPrefix     = "sms:login:vip:"
)

var (
	mainlandPhonePattern = regexp.MustCompile(`^1[3-9]\d{9}$`)
	ErrSMSLoginLimited   = errors.New("sms login send is limited")
	smsLoginMemory       = newMemorySMSLoginStore()
)

type SMSLoginLimit struct {
	RetryAfterSeconds int
}

func (err *SMSLoginLimit) Error() string {
	return ErrSMSLoginLimited.Error()
}

// NormalizeLoginPhone accepts a mainland mobile number, optionally prefixed with 86.
func NormalizeLoginPhone(raw string) (string, error) {
	var digits strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	phone := digits.String()
	if strings.HasPrefix(phone, "86") && len(phone) == 13 {
		phone = phone[2:]
	}
	if !mainlandPhonePattern.MatchString(phone) {
		return "", fmt.Errorf("invalid mobile number")
	}
	return phone, nil
}

func RandomSMSLoginCode() (string, error) {
	var code strings.Builder
	code.Grow(smsLoginCodeDigits)
	for range smsLoginCodeDigits {
		n, err := crand.Int(crand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		code.WriteByte(byte('0' + n.Int64()))
	}
	return code.String(), nil
}

func MaskLoginPhone(phone string) string {
	if len(phone) < 7 {
		return "***"
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}

// ReserveSMSLoginSend applies the phone, IP, and global send caps atomically.
// A burst of concurrent calls cannot pass a check before any of them is counted.
func ReserveSMSLoginSend(phone, ip string) error {
	return reserveSMSLoginSend(phone, smsLimitIP(ip), time.Now())
}

func reserveSMSLoginSend(phone, ip string, now time.Time) error {
	if common.RedisEnabled {
		return reserveSMSLoginSendRedis(phone, ip)
	}
	return smsLoginMemory.reserve(phone, ip, now)
}

// ReserveSMSLoginVerify counts a code check before the code is compared.
// Calls with a missing or malformed code consume the same budget.
func ReserveSMSLoginVerify(phone, ip string) error {
	return reserveSMSLoginVerify(phone, smsLimitIP(ip), time.Now())
}

func reserveSMSLoginVerify(phone, ip string, now time.Time) error {
	if common.RedisEnabled {
		return reserveSMSLoginVerifyRedis(phone, ip)
	}
	return smsLoginMemory.reserveVerify(phone, ip, now)
}

func smsLimitIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "unknown"
	}
	return ip
}

func SaveSMSLoginCode(phone, code string) error {
	if common.RedisEnabled {
		return common.RDB.Set(context.Background(), smsLoginCodeKeyPrefix+phone, code+":0", smsLoginCodeTTL).Err()
	}
	smsLoginMemory.save(phone, code, time.Now())
	return nil
}

func DeleteSMSLoginCode(phone string) {
	if common.RedisEnabled {
		_ = common.RDB.Del(context.Background(), smsLoginCodeKeyPrefix+phone).Err()
		return
	}
	smsLoginMemory.delete(phone)
}

func ReleaseSMSLoginCooldown(phone string) {
	if common.RedisEnabled {
		_ = common.RDB.Del(context.Background(), smsLoginCooldownKeyPrefix+phone).Err()
		return
	}
	smsLoginMemory.releaseCooldown(phone)
}

type SMSCodeStatus int

const (
	SMSCodeMismatch SMSCodeStatus = iota
	SMSCodeAccepted
	SMSCodeLocked
)

// ConsumeSMSLoginCode accepts a code once. A mismatch consumes an attempt.
func ConsumeSMSLoginCode(phone, code string) (SMSCodeStatus, error) {
	if len(code) != smsLoginCodeDigits {
		return SMSCodeMismatch, nil
	}
	if common.RedisEnabled {
		return consumeSMSLoginCodeRedis(phone, code)
	}
	return smsLoginMemory.consume(phone, code, time.Now()), nil
}

// smsLimitTakeScript increments every window, then rolls all of them back when
// any window is already full. Redis runs the script atomically, so concurrent
// callers cannot all observe a stale count and send together.
const smsLimitTakeScript = `
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

local function rollback(keys)
  for i = 1, #keys do
    redis.call('DECR', keys[i])
  end
end

local coolTTL = redis.call('PTTL', KEYS[1])
if coolTTL > 0 then
  return {0, coolTTL}
end

local specs = {
  {KEYS[2], ARGV[2], ARGV[3]},
  {KEYS[3], ARGV[4], ARGV[5]},
  {KEYS[4], ARGV[6], ARGV[7]},
  {KEYS[5], ARGV[8], ARGV[9]},
  {KEYS[6], ARGV[10], ARGV[11]},
  {KEYS[7], ARGV[12], ARGV[13]}
}
local touched = {}
local reject = 0
for i = 1, #specs do
  local ttl = take(specs[i][1], specs[i][2], specs[i][3])
  touched[i] = specs[i][1]
  if ttl > 0 and (reject == 0 or ttl < reject) then
    reject = ttl
  end
end
if reject > 0 then
  rollback(touched)
  return {0, reject}
end

local ok = redis.call('SET', KEYS[1], '1', 'PX', ARGV[1], 'NX')
if not ok then
  rollback(touched)
  local ttl = redis.call('PTTL', KEYS[1])
  if ttl < 1 then
    ttl = 1000
  end
  return {0, ttl}
end
return {1, 0}
`

const smsVerifyTakeScript = `
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

local phoneTTL = take(KEYS[1], ARGV[1], ARGV[2])
local ipTTL = take(KEYS[2], ARGV[3], ARGV[4])
if phoneTTL > 0 or ipTTL > 0 then
  redis.call('DECR', KEYS[1])
  redis.call('DECR', KEYS[2])
  local retry = phoneTTL
  if ipTTL > 0 and (retry == 0 or ipTTL < retry) then
    retry = ipTTL
  end
  if retry < 1 then
    retry = 1000
  end
  return {0, retry}
end
return {1, 0}
`

func reserveSMSLoginSendRedis(phone, ip string) error {
	values, err := common.RDB.Eval(
		context.Background(),
		smsLimitTakeScript,
		[]string{
			smsLoginCooldownKeyPrefix + phone,
			smsLoginPhoneHourKeyPrefix + phone,
			smsLoginDailyKeyPrefix + phone,
			smsLoginIPMinuteKeyPrefix + ip,
			smsLoginIPKeyPrefix + ip,
			smsLoginIPDayKeyPrefix + ip,
			smsLoginGlobalKey,
		},
		smsLoginCooldown.Milliseconds(),
		smsLoginPhoneHourLimit,
		smsLoginPhoneHourWindow.Milliseconds(),
		smsLoginDailyPhoneLimit,
		smsLoginDailyWindow.Milliseconds(),
		smsLoginIPMinuteLimit,
		smsLoginIPMinuteWindow.Milliseconds(),
		smsLoginHourlyIPLimit,
		smsLoginIPWindow.Milliseconds(),
		smsLoginIPDayLimit,
		smsLoginIPDayWindow.Milliseconds(),
		smsLoginGlobalMinuteLimit,
		smsLoginGlobalWindow.Milliseconds(),
	).Slice()
	if err != nil {
		return err
	}
	return smsLimitResult(values)
}

func reserveSMSLoginVerifyRedis(phone, ip string) error {
	values, err := common.RDB.Eval(
		context.Background(),
		smsVerifyTakeScript,
		[]string{smsLoginVerifyPhonePrefix + phone, smsLoginVerifyIPPrefix + ip},
		smsLoginVerifyPhoneLimit,
		smsLoginVerifyWindow.Milliseconds(),
		smsLoginVerifyIPLimit,
		smsLoginVerifyWindow.Milliseconds(),
	).Slice()
	if err != nil {
		return err
	}
	return smsLimitResult(values)
}

func smsLimitResult(values []any) error {
	if len(values) != 2 {
		return fmt.Errorf("unexpected sms limit reply length %d", len(values))
	}
	status, err := redisInteger(values[0])
	if err != nil {
		return err
	}
	if status == 1 {
		return nil
	}
	retryMs, err := redisInteger(values[1])
	if err != nil {
		return err
	}
	retry := secondsCeil(time.Duration(retryMs) * time.Millisecond)
	if retry < 1 {
		retry = 1
	}
	return &SMSLoginLimit{RetryAfterSeconds: retry}
}

func redisInteger(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case int:
		return int64(typed), nil
	case string:
		return strconv.ParseInt(typed, 10, 64)
	case []byte:
		return strconv.ParseInt(string(typed), 10, 64)
	default:
		return 0, fmt.Errorf("unexpected redis integer type %T", value)
	}
}

func consumeSMSLoginCodeRedis(phone, code string) (SMSCodeStatus, error) {
	ctx := context.Background()
	key := smsLoginCodeKeyPrefix + phone
	const script = `
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 0
end
local sep = string.find(raw, ':', 1, true)
if not sep then
  redis.call('DEL', KEYS[1])
  return 0
end
local stored = string.sub(raw, 1, sep - 1)
local attempts = tonumber(string.sub(raw, sep + 1)) or 0
if stored == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return 1
end
attempts = attempts + 1
if attempts >= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  return 2
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1 then
  ttl = tonumber(ARGV[3])
end
redis.call('SET', KEYS[1], stored .. ':' .. attempts, 'PX', ttl)
return 3
`
	result, err := common.RDB.Eval(ctx, script, []string{key}, code, smsLoginMaxAttempts, smsLoginCodeTTL.Milliseconds()).Int()
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

func secondsCeil(ttl time.Duration) int {
	if ttl <= 0 {
		return 0
	}
	seconds := int((ttl + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

type memorySMSLoginStore struct {
	mu       sync.Mutex
	codes    map[string]smsCodeEntry
	cooldown map[string]time.Time
	windows  map[string]smsCounter
}

type smsCodeEntry struct {
	code     string
	attempts int
	expires  time.Time
}

type smsCounter struct {
	count   int
	expires time.Time
}

func newMemorySMSLoginStore() *memorySMSLoginStore {
	return &memorySMSLoginStore{
		codes:    map[string]smsCodeEntry{},
		cooldown: map[string]time.Time{},
		windows:  map[string]smsCounter{},
	}
}

func (store *memorySMSLoginStore) reserve(phone, ip string, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if until, ok := store.cooldown[phone]; ok && until.After(now) {
		return &SMSLoginLimit{RetryAfterSeconds: secondsCeil(until.Sub(now))}
	}
	windows := []struct {
		key    string
		limit  int
		window time.Duration
	}{
		{"ph:" + phone, smsLoginPhoneHourLimit, smsLoginPhoneHourWindow},
		{"pd:" + phone, smsLoginDailyPhoneLimit, smsLoginDailyWindow},
		{"im:" + ip, smsLoginIPMinuteLimit, smsLoginIPMinuteWindow},
		{"ih:" + ip, smsLoginHourlyIPLimit, smsLoginIPWindow},
		{"id:" + ip, smsLoginIPDayLimit, smsLoginIPDayWindow},
		{"g", smsLoginGlobalMinuteLimit, smsLoginGlobalWindow},
	}
	for _, window := range windows {
		if retry := counterRetry(store.windows, window.key, window.limit, now); retry > 0 {
			return &SMSLoginLimit{RetryAfterSeconds: retry}
		}
	}
	store.cooldown[phone] = now.Add(smsLoginCooldown)
	for _, window := range windows {
		incrementCounter(store.windows, window.key, now, window.window)
	}
	return nil
}

func (store *memorySMSLoginStore) reserveVerify(phone, ip string, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	windows := []struct {
		key    string
		limit  int
		window time.Duration
	}{
		{"vp:" + phone, smsLoginVerifyPhoneLimit, smsLoginVerifyWindow},
		{"vi:" + ip, smsLoginVerifyIPLimit, smsLoginVerifyWindow},
	}
	for _, window := range windows {
		if retry := counterRetry(store.windows, window.key, window.limit, now); retry > 0 {
			return &SMSLoginLimit{RetryAfterSeconds: retry}
		}
	}
	for _, window := range windows {
		incrementCounter(store.windows, window.key, now, window.window)
	}
	return nil
}

func counterRetry(counters map[string]smsCounter, key string, limit int, now time.Time) int {
	counter, ok := counters[key]
	if !ok || !counter.expires.After(now) || counter.count < limit {
		return 0
	}
	return secondsCeil(counter.expires.Sub(now))
}

func incrementCounter(counters map[string]smsCounter, key string, now time.Time, window time.Duration) {
	counter, ok := counters[key]
	if !ok || !counter.expires.After(now) {
		counters[key] = smsCounter{count: 1, expires: now.Add(window)}
		return
	}
	counter.count++
	counters[key] = counter
}

func (store *memorySMSLoginStore) save(phone, code string, now time.Time) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.codes[phone] = smsCodeEntry{code: code, expires: now.Add(smsLoginCodeTTL)}
}

func (store *memorySMSLoginStore) delete(phone string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.codes, phone)
}

func (store *memorySMSLoginStore) releaseCooldown(phone string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.cooldown, phone)
}

func (store *memorySMSLoginStore) consume(phone, code string, now time.Time) SMSCodeStatus {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.codes[phone]
	if !ok || !entry.expires.After(now) {
		delete(store.codes, phone)
		return SMSCodeMismatch
	}
	matched := len(code) == len(entry.code) && subtle.ConstantTimeCompare([]byte(entry.code), []byte(code)) == 1
	if matched {
		delete(store.codes, phone)
		return SMSCodeAccepted
	}
	entry.attempts++
	if entry.attempts >= smsLoginMaxAttempts {
		delete(store.codes, phone)
		return SMSCodeLocked
	}
	store.codes[phone] = entry
	return SMSCodeMismatch
}

// ResetSMSLoginMemoryForTest clears the in-memory SMS login limiter.
func ResetSMSLoginMemoryForTest() {
	smsLoginMemory.mu.Lock()
	defer smsLoginMemory.mu.Unlock()
	smsLoginMemory.codes = map[string]smsCodeEntry{}
	smsLoginMemory.cooldown = map[string]time.Time{}
	smsLoginMemory.windows = map[string]smsCounter{}
}
