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

	"github.com/go-redis/redis/v8"
)

const (
	smsLoginCodeTTL         = 5 * time.Minute
	smsLoginCooldown        = 60 * time.Second
	smsLoginDailyWindow     = 24 * time.Hour
	smsLoginIPWindow        = time.Hour
	smsLoginCodeDigits      = 6
	smsLoginMaxAttempts     = 5
	smsLoginDailyPhoneLimit = 10
	smsLoginHourlyIPLimit   = 20

	smsLoginCodeKeyPrefix     = "sms:login:code:"
	smsLoginCooldownKeyPrefix = "sms:login:cool:"
	smsLoginDailyKeyPrefix    = "sms:login:day:"
	smsLoginIPKeyPrefix       = "sms:login:ip:"
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

// ReserveSMSLoginSend applies the per-phone cooldown, daily cap, and per-IP cap.
func ReserveSMSLoginSend(phone, ip string) error {
	if common.RedisEnabled {
		return reserveSMSLoginSendRedis(phone, ip)
	}
	return smsLoginMemory.reserve(phone, ip, time.Now())
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

func reserveSMSLoginSendRedis(phone, ip string) error {
	ctx := context.Background()
	coolKey := smsLoginCooldownKeyPrefix + phone
	ttl, err := common.RDB.PTTL(ctx, coolKey).Result()
	if err != nil {
		return err
	}
	if ttl > 0 {
		return &SMSLoginLimit{RetryAfterSeconds: secondsCeil(ttl)}
	}
	if retry, err := redisOverLimit(ctx, smsLoginDailyKeyPrefix+phone, smsLoginDailyPhoneLimit); err != nil {
		return err
	} else if retry > 0 {
		return &SMSLoginLimit{RetryAfterSeconds: retry}
	}
	if retry, err := redisOverLimit(ctx, smsLoginIPKeyPrefix+ip, smsLoginHourlyIPLimit); err != nil {
		return err
	} else if retry > 0 {
		return &SMSLoginLimit{RetryAfterSeconds: retry}
	}

	ok, err := common.RDB.SetNX(ctx, coolKey, "1", smsLoginCooldown).Result()
	if err != nil {
		return err
	}
	if !ok {
		ttl, err = common.RDB.PTTL(ctx, coolKey).Result()
		if err != nil {
			return err
		}
		retry := secondsCeil(ttl)
		if retry < 1 {
			retry = 1
		}
		return &SMSLoginLimit{RetryAfterSeconds: retry}
	}
	if err := redisIncrementWindow(ctx, smsLoginDailyKeyPrefix+phone, smsLoginDailyWindow); err != nil {
		_ = common.RDB.Del(ctx, coolKey).Err()
		return err
	}
	if err := redisIncrementWindow(ctx, smsLoginIPKeyPrefix+ip, smsLoginIPWindow); err != nil {
		_ = common.RDB.Del(ctx, coolKey).Err()
		return err
	}
	return nil
}

func redisOverLimit(ctx context.Context, key string, limit int) (int, error) {
	count, err := common.RDB.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	current, err := strconv.Atoi(count)
	if err != nil || current < limit {
		return 0, nil
	}
	ttl, err := common.RDB.PTTL(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	retry := secondsCeil(ttl)
	if retry < 1 {
		retry = 1
	}
	return retry, nil
}

func redisIncrementWindow(ctx context.Context, key string, window time.Duration) error {
	count, err := common.RDB.Incr(ctx, key).Result()
	if err != nil {
		return err
	}
	if count == 1 {
		return common.RDB.Expire(ctx, key, window).Err()
	}
	return nil
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
	daily    map[string]smsCounter
	ip       map[string]smsCounter
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
		daily:    map[string]smsCounter{},
		ip:       map[string]smsCounter{},
	}
}

func (store *memorySMSLoginStore) reserve(phone, ip string, now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if until, ok := store.cooldown[phone]; ok && until.After(now) {
		return &SMSLoginLimit{RetryAfterSeconds: secondsCeil(until.Sub(now))}
	}
	if retry := counterRetry(store.daily, phone, smsLoginDailyPhoneLimit, now); retry > 0 {
		return &SMSLoginLimit{RetryAfterSeconds: retry}
	}
	if retry := counterRetry(store.ip, ip, smsLoginHourlyIPLimit, now); retry > 0 {
		return &SMSLoginLimit{RetryAfterSeconds: retry}
	}
	store.cooldown[phone] = now.Add(smsLoginCooldown)
	incrementCounter(store.daily, phone, now, smsLoginDailyWindow)
	incrementCounter(store.ip, ip, now, smsLoginIPWindow)
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
	smsLoginMemory.daily = map[string]smsCounter{}
	smsLoginMemory.ip = map[string]smsCounter{}
}
