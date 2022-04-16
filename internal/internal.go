package internal

import (
	"time"
)

func TimestampToTime(timestamp float64) time.Time {
	return time.Unix(int64(timestamp), 0).UTC()
}

const VC_LENGTH_PASSWORD_RESET_FORM int = 50
const VC_LENGTH_PASSWORD_RESET int = 100
