package auth_test

import (
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error
		wantErrStr string
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey: "my-secret-key",
		},
		{
			name: "malformed header - wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			wantErrStr: "malformed authorization header",
		},
		{
			name: "malformed header - only one part",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantErrStr: "malformed authorization header",
		},
		{
			name: "malformed header - empty string",
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name: "ApiKey with extra spaces returns second token",
			headers: http.Header{
				"Authorization": []string{"ApiKey key with spaces"},
			},
			wantKey: "key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := auth.GetAPIKey(tc.headers)

			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tc.wantErr)
				}
				return
			}

			if tc.wantErrStr != "" {
				if err == nil || err.Error() != tc.wantErrStr {
					t.Errorf("GetAPIKey() error = %v, wantErrStr %q", err, tc.wantErrStr)
				}
				return
			}

			if err != nil {
				t.Fatalf("GetAPIKey() unexpected error: %v", err)
			}
			if got != tc.wantKey {
				t.Errorf("GetAPIKey() = %q, want %q", got, tc.wantKey)
			}
		})
	}
}
