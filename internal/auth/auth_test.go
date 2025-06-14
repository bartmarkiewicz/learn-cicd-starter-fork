package auth

import (
	"errors"
	"net/http"
	"testing"
)

var authErr = errors.New("no authorization header included")

func TestGetAPIKey_success(t *testing.T) {
	tests := map[string]struct {
		input     http.Header
		want      string
		expectErr bool
		err       error
	}{
		"no header":                         {input: http.Header{}, want: "", expectErr: true, err: authErr},
		"json header auth":                  {input: http.Header{"Authorization": {"Random", "Something"}}, want: "", expectErr: false},
		"Empty header":                      {input: http.Header{"Content-Type": {}}, want: "", expectErr: true, err: authErr},
		"Authorization header wrong format": {input: http.Header{"Authorization": {"SingleVal"}}, want: "", expectErr: true, err: errors.New("malformed authorization header")},
		"Authorization header right format": {input: http.Header{"Authorization": {"ApiKey THsEKEY"}}, want: "THEKEY", expectErr: false, err: errors.New("malformed authorization header")},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := GetAPIKey(tc.input)
			if tc.want != result {
				t.Fatalf("Test: %v expected: %v got: %v", name, tc.want, result)
			}

			if tc.expectErr {
				if err == nil || err.Error() != tc.err.Error() {
					t.Fatalf("Test: %v expected: %v got: %v", name, tc.err, err)
				}
			}
		})
	}
}
