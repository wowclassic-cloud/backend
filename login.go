// Copyright 2019 ClassicWow.Cloud Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"os"

	"fortio.org/fortio/log"
	"golang.org/x/oauth2"
)

func login() {
	log.SetLogLevel(log.Debug)
	cid := os.Getenv("OAUTH_CID")
	if len(cid) == 0 {
		log.Fatalf("Please specify client id as OAUTH_CID env var")
	}
	csec := os.Getenv("OAUTH_SEC")
	if len(csec) == 0 {
		log.Fatalf("Please specify client secret as OAUTH_SEC env var")
	}
	log.Infof("OUTH test...")
	ctx := context.Background()
	conf := &oauth2.Config{
		ClientID:     cid,
		ClientSecret: csec,
		Scopes:       []string{"wow.profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://us.battle.net/oauth/authorize",
			TokenURL: "https://us.battle.net/oauth/token",
		},
		RedirectURL: "https://app.classicwow.cloud/oauthc/",
	}

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	fmt.Printf("Visit the URL for the auth dialog: %v", url)

	// Use the authorization code that is pushed to the redirect
	// URL. Exchange will do the handshake to retrieve the
	// initial access token. The HTTP Client returned by
	// conf.Client will refresh the token as necessary.
	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatalf("error on code scan %v", err)
	}
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Fatalf("error on exchange %v", err)
	}
	log.Infof("got tok %v", tok)
	client := conf.Client(ctx, tok)
	client.Get("...")
}
