package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPasswordSMSReserveDoesNotUseLoginCooldown(t *testing.T) {
	ResetSMSLoginMemoryForTest()
	ResetPasswordSMSMemoryForTest()
	t.Cleanup(func() {
		ResetSMSLoginMemoryForTest()
		ResetPasswordSMSMemoryForTest()
	})

	require.NoError(t, ReserveSMSLoginSend("13800138000", "127.0.0.1"))
	require.NoError(t, reservePasswordSMSSend(9))
	err := reservePasswordSMSSend(9)
	var limit *SMSLoginLimit
	require.ErrorAs(t, err, &limit)
	require.Positive(t, limit.RetryAfterSeconds)

	releasePasswordSMSCooldown(9)
	require.NoError(t, reservePasswordSMSSend(9))
}

func TestPasswordSMSCodeAcceptsOnceAndLocks(t *testing.T) {
	ResetPasswordSMSMemoryForTest()
	t.Cleanup(ResetPasswordSMSMemoryForTest)

	require.NoError(t, savePasswordSMSCode(42, "13800138000", "123456"))
	status, err := consumePasswordSMSCode(42, "13900139000", "123456")
	require.NoError(t, err)
	require.Equal(t, SMSCodeMismatch, status)

	require.NoError(t, savePasswordSMSCode(42, "13800138000", "123456"))
	for range smsLoginMaxAttempts - 1 {
		status, err = consumePasswordSMSCode(42, "13800138000", "000000")
		require.NoError(t, err)
		require.Equal(t, SMSCodeMismatch, status)
	}
	status, err = consumePasswordSMSCode(42, "13800138000", "000000")
	require.NoError(t, err)
	require.Equal(t, SMSCodeLocked, status)

	require.NoError(t, savePasswordSMSCode(42, "13800138000", "123456"))
	status, err = consumePasswordSMSCode(42, "13800138000", "123456")
	require.NoError(t, err)
	require.Equal(t, SMSCodeAccepted, status)
	status, err = consumePasswordSMSCode(42, "13800138000", "123456")
	require.NoError(t, err)
	require.Equal(t, SMSCodeMismatch, status)

	passwordSMSMemory.save(7, "13800138000", "123456", time.Now().Add(-2*smsLoginCodeTTL))
	status, err = consumePasswordSMSCode(7, "13800138000", "123456")
	require.NoError(t, err)
	require.Equal(t, SMSCodeMismatch, status)
}
