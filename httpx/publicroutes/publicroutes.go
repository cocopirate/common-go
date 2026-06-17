package publicroutes

import (
	"github.com/cocopirate/common-go/httpx/response"
	"github.com/gin-gonic/gin"
)

const (
	EndpointPath = "/internal/gateway/public-routes"
	MatchExact   = "exact"
	MatchPrefix  = "prefix"
)

type Spec struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Match  string `json:"match"`
}

func Handler(specs []Spec) gin.HandlerFunc {
	return func(c *gin.Context) {
		response.OK(c, specs)
	}
}
