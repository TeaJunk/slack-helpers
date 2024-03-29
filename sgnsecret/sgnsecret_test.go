package sgnsecret

import "testing"

func TestHmac(t *testing.T) {
	// Sample data taken from https://api.slack.com/docs/verifying-requests-from-slack
	var request Request
	request.Headers = make(map[string]string)
	request.Body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"
	request.Headers[signatureHeader] = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
	request.Headers[timestampHeader] = "1531420618"
	secret := "8f742231b10e8888abcd99yyyzzz85a5"

	if result, err := HmacCompare(request, secret, ""); result != true || err != nil {
		t.Errorf("Expected boolean true, got %v\n, error is %v ", result, err)
	}
}
