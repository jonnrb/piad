package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

const TokenEndpoint = "https://www.privateinternetaccess.com/api/client/v2/token"

type Token string

type tokenRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type tokenResponse struct {
	Token Token `json:"token"`
}

func GetToken(ctx context.Context, username, password string) (Token, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(tokenRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", TokenEndpoint, &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := (&http.Client{}).Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	var tres tokenResponse
	err = json.NewDecoder(res.Body).Decode(&tres)
	return tres.Token, err
}
