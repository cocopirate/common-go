package redisx

import "github.com/redis/go-redis/v9"

func ParseOptions(redisURL string) (*redis.Options, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	ApplyCompatibility(opt)
	return opt, nil
}

func NewClient(redisURL string) (*redis.Client, error) {
	opt, err := ParseOptions(redisURL)
	if err != nil {
		return nil, err
	}
	return redis.NewClient(opt), nil
}

func ApplyCompatibility(opt *redis.Options) {
	if opt == nil {
		return
	}
	// Alibaba Cloud Redis expects AUTH username:password on RESP2 connections.
	if opt.Username != "" {
		opt.Password = opt.Username + ":" + opt.Password
		opt.Username = ""
	}
	opt.Protocol = 2
}
