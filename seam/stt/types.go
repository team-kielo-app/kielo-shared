package stt

import (
	"context"
	"errors"
)

type Request struct {
	Audio       []byte
	ContentType string
	Language    string
	Model       string
	Keyterms    []string
	Task        string
}

type Result struct {
	Transcript string
	Confidence float64
	Language   string
	Provider   string
	LatencyMs  int64
}

type ErrorClass string

const (
	ErrorClassUnknown       ErrorClass = "unknown"
	ErrorClassTimeout       ErrorClass = "timeout"
	ErrorClassConnection    ErrorClass = "connection"
	ErrorClassClientError   ErrorClass = "http_4xx"
	ErrorClassServerError   ErrorClass = "http_5xx"
	ErrorClassReadBody      ErrorClass = "read_body"
	ErrorClassDecode        ErrorClass = "decode"
	ErrorClassEmptyResponse ErrorClass = "empty_response"
)

type Error struct {
	Class ErrorClass
	Err   error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return string(e.Class) + ": " + e.Err.Error()
	}
	return string(e.Class)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func ClassOf(err error) ErrorClass {
	if err == nil {
		return ""
	}
	var seamErr *Error
	if errors.As(err, &seamErr) {
		return seamErr.Class
	}
	return ErrorClassUnknown
}

type Provider interface {
	Transcribe(context.Context, Request) (*Result, error)
}
