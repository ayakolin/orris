package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisRateLimiter struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedisRateLimiter(client *redis.Client) RateLimiter {
	return &RedisRateLimiter{
		client: client,
		ctx:    context.Background(),
	}
}

func (l *RedisRateLimiter) Allow(key string, config RateLimitConfig) (bool, error) {
	now := time.Now()

	windows := []struct {
		duration time.Duration
		limit    int
	}{
		{time.Minute, config.RequestsPerMinute},
		{time.Hour, config.RequestsPerHour},
		{24 * time.Hour, config.RequestsPerDay},
	}

	for _, window := range windows {
		if window.limit <= 0 {
			continue
		}

		allowed, err := l.checkWindow(key, window.duration, window.limit, now)
		if err != nil {
			return false, err
		}

		if !allowed {
			return false, nil
		}
	}

	return true, nil
}

// slidingWindowScript performs the sliding-window check atomically: it trims
// entries older than the window, counts what remains, and only records the
// current request if the count is still under the limit. Doing this in a single
// Lua script prevents the check-then-increment race where two concurrent
// requests both read the same sub-limit count and are both admitted.
//
// KEYS[1] = redis key
// ARGV[1] = window-start score (unix nanos), ARGV[2] = now (unix nanos)
// ARGV[3] = limit, ARGV[4] = key TTL in seconds
// returns 1 when the request is allowed, 0 when it is rejected.
var slidingWindowScript = redis.NewScript(`
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[1])
local count = redis.call('ZCARD', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[4])
if count < tonumber(ARGV[3]) then
    redis.call('ZADD', KEYS[1], ARGV[2], ARGV[2])
    return 1
end
return 0
`)

func (l *RedisRateLimiter) checkWindow(key string, window time.Duration, limit int, now time.Time) (bool, error) {
	redisKey := l.getKey(key, window)
	windowStart := now.Add(-window).UnixNano()
	nowNano := now.UnixNano()
	ttlSeconds := int64((window + time.Minute).Seconds())

	allowed, err := slidingWindowScript.Run(l.ctx, l.client, []string{redisKey},
		windowStart, nowNano, limit, ttlSeconds).Int64()
	if err != nil {
		return false, fmt.Errorf("failed to run rate limit script: %w", err)
	}

	return allowed == 1, nil
}

func (l *RedisRateLimiter) GetRemaining(key string, window time.Duration) (int64, error) {
	redisKey := l.getKey(key, window)
	now := time.Now()
	windowStart := now.Add(-window).UnixNano()

	pipe := l.client.Pipeline()
	pipe.ZRemRangeByScore(l.ctx, redisKey, "0", fmt.Sprintf("%d", windowStart))
	zcard := pipe.ZCard(l.ctx, redisKey)

	_, err := pipe.Exec(l.ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get remaining: %w", err)
	}

	return zcard.Val(), nil
}

func (l *RedisRateLimiter) Reset(key string) error {
	pattern := fmt.Sprintf("ratelimit:%s:*", key)

	iter := l.client.Scan(l.ctx, 0, pattern, 0).Iterator()
	for iter.Next(l.ctx) {
		err := l.client.Del(l.ctx, iter.Val()).Err()
		if err != nil {
			return fmt.Errorf("failed to delete key %s: %w", iter.Val(), err)
		}
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan keys: %w", err)
	}

	return nil
}

func (l *RedisRateLimiter) getKey(identifier string, window time.Duration) string {
	return fmt.Sprintf("ratelimit:%s:%s", identifier, window.String())
}
