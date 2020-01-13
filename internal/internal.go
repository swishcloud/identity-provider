package internal

import (
	"time"
)

func TimestampToTime(timestamp float64) time.Time {
	return time.Unix(int64(timestamp), 0).UTC()
}
