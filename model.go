package main

type Token struct {
	Token      string `json:"token"`
	ExpireTime int64 `json:"expireTime"`
	User       string `json:"userName"`
	Host       string `json:"host"`
}

type Event struct {
	EventType string `json:"type"`
	Date      int64 `json:"date"`
	Data      string `json:"data"`
}

type Message struct {
	Message string `json:"message"`
}
