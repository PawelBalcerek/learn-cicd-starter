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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := auth.GetAPIKey(tt.headers)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if tt.wantErrStr != "" {
				if err == nil || err.Error() != tt.wantErrStr {
					t.Errorf("GetAPIKey() error = %v, wantErrStr %q", err, tt.wantErrStr)
				}
				return
			}

			if err != nil {
				t.Fatalf("GetAPIKey() unexpected error: %v", err)
			}
			if got != tt.wantKey {
				t.Errorf("GetAPIKey() = %q, want %q", got, tt.wantKey)
			}
		})
	}
}
