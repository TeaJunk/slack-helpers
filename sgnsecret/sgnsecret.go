// Package sgnsecret works with signing secrets for Slack
package sgnsecret

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// Request type is just Proxy Request type, exported for availability in other projects
type Request events.APIGatewayProxyRequest

const timestampHeader = "X-Slack-Request-Timestamp"
const signatureHeader = "X-Slack-Signature"

//HmacCompare takes full request from Slack slash command, secret string and optionally version (v0 currently) and compares with returing signature.
func HmacCompare(request Request, slackSigningSecret, signingVersion string) (bool, error) {
	if signingVersion == "" {
		signingVersion = "v0"
	}
	requestHash := hmac.New(sha256.New, []byte(slackSigningSecret))
	requestHashData := strings.Join([]string{
		signingVersion,
		request.Headers[timestampHeader],
		request.Body},
		":")
	_, err := requestHash.Write([]byte(requestHashData))
	if err != nil {
		return false, err
	}
	signature := []byte(signingVersion + "=" + hex.EncodeToString(requestHash.Sum(nil)))
	return hmac.Equal(signature, []byte(request.Headers[signatureHeader])), nil
}
