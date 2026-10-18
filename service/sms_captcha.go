package service

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"

	"github.com/go-redis/redis/v8"
)

const (
	smsCaptchaWidth       = 280
	smsCaptchaHeight      = 120
	smsCaptchaBody        = 36
	smsCaptchaKnob        = 8
	smsCaptchaPieceWidth  = smsCaptchaBody + smsCaptchaKnob
	smsCaptchaPieceHeight = 44
	smsCaptchaTTL         = 2 * time.Minute
	smsCaptchaTolerance   = 5
	smsCaptchaIssueLimit  = 6
	smsCaptchaFailLimit   = 3
	smsCaptchaLimitWindow = 10 * time.Minute
	smsCaptchaMinDuration = 280
	smsCaptchaMaxDuration = 20000

	smsCaptchaKeyPrefix   = "sms:login:captcha:"
	smsCaptchaIssuePrefix = "sms:login:captcha-issue:"
	smsCaptchaFailPrefix  = "sms:login:captcha-fail:"
)

var (
	ErrSMSCaptchaRejected = errors.New("sms captcha rejected")
	smsCaptchaMemory      = newMemorySMSCaptchaStore()
)

// SMSCaptchaPoint is one sample of the slider drag, in image pixels and
// milliseconds from the start of the gesture.
type SMSCaptchaPoint struct {
	X int `json:"x"`
	Y int `json:"y"`
	T int `json:"t"`
}

// SMSCaptchaChallenge is a one-time slider puzzle. The gap position stays on
// the server.
type SMSCaptchaChallenge struct {
	Token       string
	Background  string
	Piece       string
	Width       int
	Height      int
	PieceWidth  int
	PieceHeight int
	PieceY      int
}

// IssueSMSCaptcha draws a puzzle and remembers the gap for this client IP.
func IssueSMSCaptcha(ip string) (*SMSCaptchaChallenge, error) {
	ip = smsLimitIP(ip)
	if err := consumeSMSCaptchaBudget(smsCaptchaIssuePrefix, ip, smsCaptchaIssueLimit); err != nil {
		return nil, err
	}
	targetX, err := randRange(40, smsCaptchaWidth-smsCaptchaPieceWidth-2)
	if err != nil {
		return nil, err
	}
	targetY, err := randRange(12, smsCaptchaHeight-smsCaptchaPieceHeight-12)
	if err != nil {
		return nil, err
	}
	background, piece, err := renderSMSCaptcha(targetX, targetY)
	if err != nil {
		return nil, err
	}
	token, err := randomSMSCaptchaToken()
	if err != nil {
		return nil, err
	}
	if err := saveSMSCaptcha(token, targetX, ip); err != nil {
		return nil, err
	}
	return &SMSCaptchaChallenge{
		Token:       token,
		Background:  background,
		Piece:       piece,
		Width:       smsCaptchaWidth,
		Height:      smsCaptchaHeight,
		PieceWidth:  smsCaptchaPieceWidth,
		PieceHeight: smsCaptchaPieceHeight,
		PieceY:      targetY,
	}, nil
}

// VerifySMSCaptcha accepts a slider release once. The token, client IP, gap,
// and drag shape must all match. A rejection consumes the puzzle.
func VerifySMSCaptcha(ip, token string, x int, track []SMSCaptchaPoint) error {
	ip = smsLimitIP(ip)
	if retry, err := smsCaptchaBudgetRetry(smsCaptchaFailPrefix, ip, smsCaptchaFailLimit); err != nil {
		return err
	} else if retry > 0 {
		return &SMSLoginLimit{RetryAfterSeconds: retry}
	}
	targetX, owner, ok, err := takeSMSCaptcha(token)
	if err != nil {
		return err
	}
	if !ok || owner != ip || !plausibleSMSCaptchaTrack(track, x) || absInt(x-targetX) > smsCaptchaTolerance {
		if budgetErr := consumeSMSCaptchaBudget(smsCaptchaFailPrefix, ip, smsCaptchaFailLimit); budgetErr != nil {
			var limit *SMSLoginLimit
			if errors.As(budgetErr, &limit) {
				return budgetErr
			}
		}
		return ErrSMSCaptchaRejected
	}
	return nil
}

func plausibleSMSCaptchaTrack(track []SMSCaptchaPoint, finalX int) bool {
	if len(track) < 5 || len(track) > 300 || finalX < 20 {
		return false
	}
	if absInt(track[0].X) > 12 {
		return false
	}
	duration := track[len(track)-1].T - track[0].T
	if duration < smsCaptchaMinDuration || duration > smsCaptchaMaxDuration {
		return false
	}
	if absInt(track[len(track)-1].X-finalX) > 8 {
		return false
	}
	sawMiddle := false
	previous := track[0]
	for _, point := range track[1:] {
		if point.T <= previous.T {
			return false
		}
		step := point.X - previous.X
		if step > 80 || step < -40 {
			return false
		}
		if point.X > finalX/5 && point.X < finalX*4/5 {
			sawMiddle = true
		}
		previous = point
	}
	return sawMiddle
}

func saveSMSCaptcha(token string, targetX int, ip string) error {
	if common.RedisEnabled {
		return common.RDB.Set(context.Background(), smsCaptchaKeyPrefix+token, fmt.Sprintf("%d\n%s", targetX, ip), smsCaptchaTTL).Err()
	}
	smsCaptchaMemory.save(token, targetX, ip, time.Now())
	return nil
}

func takeSMSCaptcha(token string) (int, string, bool, error) {
	if token == "" || len(token) > 128 {
		return 0, "", false, nil
	}
	if common.RedisEnabled {
		const script = `
local value = redis.call('GET', KEYS[1])
if value then
  redis.call('DEL', KEYS[1])
end
return value
`
		value, err := common.RDB.Eval(context.Background(), script, []string{smsCaptchaKeyPrefix + token}).Text()
		if errors.Is(err, redis.Nil) {
			return 0, "", false, nil
		}
		if err != nil {
			return 0, "", false, err
		}
		targetX, ip, ok := parseSMSCaptchaValue(value)
		return targetX, ip, ok, nil
	}
	targetX, ip, ok := smsCaptchaMemory.take(token, time.Now())
	return targetX, ip, ok, nil
}

func parseSMSCaptchaValue(value string) (int, string, bool) {
	targetRaw, ip, ok := strings.Cut(value, "\n")
	if !ok || ip == "" {
		return 0, "", false
	}
	targetX, err := strconv.Atoi(targetRaw)
	if err != nil {
		return 0, "", false
	}
	return targetX, ip, true
}

func consumeSMSCaptchaBudget(prefix, ip string, limit int) error {
	if common.RedisEnabled {
		ctx := context.Background()
		key := prefix + ip
		count, err := common.RDB.Incr(ctx, key).Result()
		if err != nil {
			return err
		}
		if count == 1 {
			if err := common.RDB.Expire(ctx, key, smsCaptchaLimitWindow).Err(); err != nil {
				return err
			}
		}
		if count <= int64(limit) {
			return nil
		}
		ttl, err := common.RDB.PTTL(ctx, key).Result()
		if err != nil {
			return err
		}
		retry := secondsCeil(ttl)
		if retry < 1 {
			retry = 1
		}
		return &SMSLoginLimit{RetryAfterSeconds: retry}
	}
	retry := smsCaptchaMemory.consumeBudget(prefix+ip, limit, time.Now())
	if retry > 0 {
		return &SMSLoginLimit{RetryAfterSeconds: retry}
	}
	return nil
}

func smsCaptchaBudgetRetry(prefix, ip string, limit int) (int, error) {
	if common.RedisEnabled {
		ctx := context.Background()
		key := prefix + ip
		countRaw, err := common.RDB.Get(ctx, key).Result()
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		count, convErr := strconv.Atoi(countRaw)
		if convErr != nil || count < limit {
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
	return smsCaptchaMemory.budgetRetry(prefix+ip, limit, time.Now()), nil
}

func randomSMSCaptchaToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := crand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randRange(min, max int) (int, error) {
	if max < min {
		return 0, fmt.Errorf("invalid captcha range")
	}
	span := max - min + 1
	n, err := crand.Int(crand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return 0, err
	}
	return min + int(n.Int64()), nil
}

func renderSMSCaptcha(targetX, targetY int) (string, string, error) {
	background := image.NewRGBA(image.Rect(0, 0, smsCaptchaWidth, smsCaptchaHeight))
	for y := 0; y < smsCaptchaHeight; y++ {
		for x := 0; x < smsCaptchaWidth; x++ {
			background.SetRGBA(x, y, color.RGBA{
				R: uint8(186 + x*50/smsCaptchaWidth),
				G: uint8(214 - y*40/smsCaptchaHeight),
				B: uint8(246 - x*30/smsCaptchaWidth),
				A: 255,
			})
		}
	}
	for range 16 {
		cx, err := randRange(0, smsCaptchaWidth-1)
		if err != nil {
			return "", "", err
		}
		cy, err := randRange(0, smsCaptchaHeight-1)
		if err != nil {
			return "", "", err
		}
		radius, err := randRange(6, 22)
		if err != nil {
			return "", "", err
		}
		shade, err := randRange(80, 230)
		if err != nil {
			return "", "", err
		}
		fillCircle(background, cx, cy, radius, color.RGBA{R: uint8(shade), G: uint8(160 + shade/5), B: uint8(210), A: 90})
	}

	piece := image.NewRGBA(image.Rect(0, 0, smsCaptchaPieceWidth, smsCaptchaPieceHeight))
	for localY := 0; localY < smsCaptchaPieceHeight; localY++ {
		for localX := 0; localX < smsCaptchaPieceWidth; localX++ {
			if !smsCaptchaContains(localX, localY) {
				continue
			}
			srcX := targetX + localX
			srcY := targetY + localY
			if !image.Pt(srcX, srcY).In(background.Bounds()) {
				continue
			}
			piece.SetRGBA(localX, localY, background.RGBAAt(srcX, srcY))
			background.SetRGBA(srcX, srcY, darkened(background.RGBAAt(srcX, srcY)))
		}
	}
	strokePiece(piece)

	backgroundEncoded, err := encodePNG(background)
	if err != nil {
		return "", "", err
	}
	pieceEncoded, err := encodePNG(piece)
	if err != nil {
		return "", "", err
	}
	return backgroundEncoded, pieceEncoded, nil
}

func smsCaptchaContains(localX, localY int) bool {
	if localX < 0 || localY < 0 || localY >= smsCaptchaPieceHeight || localX >= smsCaptchaPieceWidth {
		return false
	}
	if localX < smsCaptchaBody {
		return true
	}
	dx := localX - smsCaptchaBody
	dy := localY - smsCaptchaPieceHeight/2
	return dx*dx+dy*dy <= smsCaptchaKnob*smsCaptchaKnob
}

func fillCircle(img *image.RGBA, cx, cy, radius int, shade color.RGBA) {
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			if x < 0 || y < 0 || x >= smsCaptchaWidth || y >= smsCaptchaHeight {
				continue
			}
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy > radius*radius {
				continue
			}
			current := img.RGBAAt(x, y)
			img.SetRGBA(x, y, blendRGBA(current, shade))
		}
	}
}

func blendRGBA(dst, src color.RGBA) color.RGBA {
	alpha := int(src.A)
	inv := 255 - alpha
	return color.RGBA{
		R: uint8((int(src.R)*alpha + int(dst.R)*inv) / 255),
		G: uint8((int(src.G)*alpha + int(dst.G)*inv) / 255),
		B: uint8((int(src.B)*alpha + int(dst.B)*inv) / 255),
		A: 255,
	}
}

func darkened(c color.RGBA) color.RGBA {
	return color.RGBA{R: c.R / 3, G: c.G / 3, B: c.B/3 + 30, A: 255}
}

func strokePiece(piece *image.RGBA) {
	bounds := piece.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if piece.RGBAAt(x, y).A == 0 || !pieceEdge(piece, x, y) {
				continue
			}
			piece.SetRGBA(x, y, color.RGBA{R: 255, G: 255, B: 255, A: 255})
		}
	}
}

func pieceEdge(piece *image.RGBA, x, y int) bool {
	for _, delta := range []image.Point{{-1, 0}, {1, 0}, {0, -1}, {0, 1}} {
		neighbor := piece.RGBAAt(x+delta.X, y+delta.Y)
		if neighbor.A == 0 {
			return true
		}
	}
	return false
}

func encodePNG(img image.Image) (string, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

type memorySMSCaptchaStore struct {
	mu         sync.Mutex
	challenges map[string]smsCaptchaEntry
	budgets    map[string]smsCounter
}

type smsCaptchaEntry struct {
	x       int
	ip      string
	expires time.Time
}

func newMemorySMSCaptchaStore() *memorySMSCaptchaStore {
	return &memorySMSCaptchaStore{
		challenges: map[string]smsCaptchaEntry{},
		budgets:    map[string]smsCounter{},
	}
}

func (store *memorySMSCaptchaStore) save(token string, targetX int, ip string, now time.Time) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.challenges[token] = smsCaptchaEntry{x: targetX, ip: ip, expires: now.Add(smsCaptchaTTL)}
}

func (store *memorySMSCaptchaStore) take(token string, now time.Time) (int, string, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.challenges[token]
	if !ok || !entry.expires.After(now) {
		delete(store.challenges, token)
		return 0, "", false
	}
	delete(store.challenges, token)
	return entry.x, entry.ip, true
}

func (store *memorySMSCaptchaStore) consumeBudget(key string, limit int, now time.Time) int {
	store.mu.Lock()
	defer store.mu.Unlock()
	if retry := counterRetry(store.budgets, key, limit, now); retry > 0 {
		return retry
	}
	incrementCounter(store.budgets, key, now, smsCaptchaLimitWindow)
	return 0
}

func (store *memorySMSCaptchaStore) budgetRetry(key string, limit int, now time.Time) int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return counterRetry(store.budgets, key, limit, now)
}

// ResetSMSCaptchaForTest clears issued puzzles and their attempt budgets.
func ResetSMSCaptchaForTest() {
	smsCaptchaMemory.mu.Lock()
	defer smsCaptchaMemory.mu.Unlock()
	smsCaptchaMemory.challenges = map[string]smsCaptchaEntry{}
	smsCaptchaMemory.budgets = map[string]smsCounter{}
}
