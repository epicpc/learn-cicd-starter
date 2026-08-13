package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		wantKey       string
		wantErr       error
		wantErrString string
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey secret123"}},
			wantKey: "secret123",
			wantErr: nil,
		},
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "malformed header - missing prefix",
			headers:       http.Header{"Authorization": []string{"secret123"}},
			wantKey:       "",
			wantErrString: "malformed authorization header",
		},
		{
			name:          "malformed header - wrong prefix",
			headers:       http.Header{"Authorization": []string{"Bearer secret123"}},
			wantKey:       "",
			wantErrString: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if tt.wantErrString != "" {
				if err == nil || err.Error() != tt.wantErrString {
					t.Errorf("GetAPIKey() error = %v, wantErrString %v", err, tt.wantErrString)
				}
				return
			}
			if err != nil {
				t.Errorf("GetAPIKey() unexpected error = %v", err)
				return
			}
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() gotKey = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}
