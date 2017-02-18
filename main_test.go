package main

import (
	"testing"
	"time"
)

func TestLoadEmptyToken(t *testing.T) {
	removeToken()
	err := loadToken()
	if err == nil {
		t.Error("We expect error because there is nothing there.")
	}
}

func TestSaveToken(t *testing.T) {
	removeToken()
	token = Token{User: "user", Host: "host", ExpireTime: time.Now().UnixNano() / time.Millisecond.Nanoseconds()}
	err := saveToken()
	if err != nil {
		t.Error("saving should not fail")
	}
}

func TestLoadToken(t *testing.T) {
	TestSaveToken(t)
	err := loadToken()
	if err != nil {
		t.Error("we should able to load token")
	}
	if token.User != "user" || token.Host != "host" {
		t.Error("Data loading wrong")
	}
}
