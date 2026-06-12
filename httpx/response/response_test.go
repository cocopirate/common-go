package response

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestFailWritesUnifiedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("request_id", "rid-1")

	Fail(c, http.StatusForbidden, PermissionDenied, "forbidden")

	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d", w.Code)
	}
	want := `{"code":40010,"message":"forbidden","data":null,"request_id":"rid-1"}`
	if w.Body.String() != want {
		t.Fatalf("body=%s want %s", w.Body.String(), want)
	}
}

func TestHTTPCodeToBusinessCode(t *testing.T) {
	if got := HTTPCodeToBusinessCode(http.StatusUnauthorized); got != TokenInvalid {
		t.Fatalf("401 maps to %d", got)
	}
	if got := HTTPCodeToBusinessCode(http.StatusForbidden); got != PermissionDenied {
		t.Fatalf("403 maps to %d", got)
	}
	if got := HTTPCodeToBusinessCode(http.StatusGatewayTimeout); got != UpstreamError {
		t.Fatalf("504 maps to %d", got)
	}
}
