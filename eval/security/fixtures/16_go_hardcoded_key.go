// Fixture 16: SignToken(). Reviewer should flag CWE-798.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

const signingKey = "8e2f4a1c9b6d3e0f7a5c8b1d4e6f9a2c"

func SignToken(payload string) string {
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
