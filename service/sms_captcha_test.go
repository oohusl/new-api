package service

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/require"
)

func TestSMSCaptchaAcceptsOneHumanDrag(t *testing.T) {
	previousRedis := common.RedisEnabled
	common.RedisEnabled = false
	ResetSMSCaptchaForTest()
	t.Cleanup(func() {
		common.RedisEnabled = previousRedis
		ResetSMSCaptchaForTest()
	})

	challenge, err := IssueSMSCaptcha("192.0.2.8")
	require.NoError(t, err)
	require.NotEmpty(t, challenge.Token)
	decoded, err := base64.StdEncoding.DecodeString(challenge.Background)
	require.NoError(t, err)
	_, err = png.Decode(bytes.NewReader(decoded))
	require.NoError(t, err)

	target := smsCaptchaTarget(t, challenge.Token)
	require.NoError(t, VerifySMSCaptcha("192.0.2.8", challenge.Token, target, dragTrack(target)))
	require.ErrorIs(t, VerifySMSCaptcha("192.0.2.8", challenge.Token, target, dragTrack(target)), ErrSMSCaptchaRejected)

	other, err := IssueSMSCaptcha("192.0.2.8")
	require.NoError(t, err)
	otherTarget := smsCaptchaTarget(t, other.Token)
	require.ErrorIs(t, VerifySMSCaptcha("192.0.2.9", other.Token, otherTarget, dragTrack(otherTarget)), ErrSMSCaptchaRejected)
	require.ErrorIs(t, VerifySMSCaptcha("192.0.2.8", other.Token, otherTarget, dragTrack(otherTarget)), ErrSMSCaptchaRejected)

	jumped, err := IssueSMSCaptcha("192.0.2.10")
	require.NoError(t, err)
	jumpTarget := smsCaptchaTarget(t, jumped.Token)
	require.ErrorIs(t, VerifySMSCaptcha("192.0.2.10", jumped.Token, jumpTarget, []SMSCaptchaPoint{
		{X: 0, T: 0},
		{X: jumpTarget, T: 30},
	}), ErrSMSCaptchaRejected)
}

func smsCaptchaTarget(t *testing.T, token string) int {
	t.Helper()
	smsCaptchaMemory.mu.Lock()
	defer smsCaptchaMemory.mu.Unlock()
	entry, ok := smsCaptchaMemory.challenges[token]
	require.True(t, ok)
	return entry.x
}

func dragTrack(target int) []SMSCaptchaPoint {
	const steps = 12
	points := make([]SMSCaptchaPoint, 0, steps+1)
	for i := 0; i <= steps; i++ {
		points = append(points, SMSCaptchaPoint{X: target * i / steps, Y: i % 3, T: i * 40})
	}
	return points
}
