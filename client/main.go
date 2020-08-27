package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	oauth2 "golang.org/x/oauth2"
)

var (
	clientID     = "app"
	clientSecret = "0db15852-1b50-45eb-ba36-481dc54693e8"
)

func main() {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "http://localhost:8080/auth/realms/demo-realm")
	if err != nil {
		log.Fatal(err)
	}
	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:8081/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	state := "magica"

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "failed to exchange token", http.StatusBadRequest)
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id_token", http.StatusBadRequest)
			return
		}
		resp := struct {
			OAUTH2Token *oauth2.Token
			RawIDToken  string
		}{
			OAUTH2Token: oauth2Token, RawIDToken: rawIDToken,
		}
		data, err := json.MarshalIndent(resp, "", "   ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write(data)
	})

	log.Fatal(http.ListenAndServe(":8081", nil))
}
