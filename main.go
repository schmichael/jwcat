package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v3"
)

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Println("error reading key: ", err)
		os.Exit(1)
	}
	str := string(raw)

	sig, err := jose.ParseSigned(str)
	if err != nil {
		fmt.Println("error parsing JWS: ", err)
		os.Exit(1)
	}

	fmt.Println(">>> Successfully parsed ", str)

	for i, part := range strings.Split(str, ".") {
		part = strings.TrimRight(part, "=")
		raw, err = base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			fmt.Println(i, "error parsing base64: ", err)
			continue
		}

		pretty := bytes.NewBuffer(nil)
		if err := json.Indent(pretty, raw, "", "  "); err != nil {
			fmt.Println(i, "error indenting json: ", err)
			continue
		}

		fmt.Println(i, "Part:", pretty.String())
	}

	for i, s := range sig.Signatures {
		dumpHeader(fmt.Sprintf("%d Protected:   ", i), s.Protected)
		dumpHeader(fmt.Sprintf("%d UNPROTECTED: ", i), s.Header)
	}

	fmt.Println("UNVERIFIED Payload:\n", string(sig.UnsafePayloadWithoutVerification()))
}

func dumpHeader(prefix string, h jose.Header) {
	if h.KeyID == "" {
		fmt.Println(prefix, "No kid")
	} else {
		fmt.Println(prefix, "kid: ", h.KeyID)
	}

	if h.JSONWebKey == nil {
		fmt.Println(prefix, "No jwk")
	} else {
		raw, err := h.JSONWebKey.MarshalJSON()
		if err != nil {
			fmt.Println(prefix, "error parsing jwt json: ", err)
		} else {
			fmt.Println(prefix, "UNVERIFIED JWT:\n", string(raw))
		}
	}

	if h.Algorithm == "" {
		fmt.Println(prefix, "No alg")
	} else {
		fmt.Println(prefix, "alg: ", h.Algorithm)
	}

	if h.Nonce == "" {
		fmt.Println(prefix, "No nonce")
	} else {
		fmt.Println(prefix, "nonce: ", h.Nonce)
	}

	if len(h.ExtraHeaders) == 0 {
		fmt.Println(prefix, "No extra headers")
	} else {
		for ehk, ehv := range h.ExtraHeaders {
			fmt.Printf("%s Extra header %q -> %q\n", prefix, ehk, ehv)
		}
	}
}
