package krakend

import (
	"context"
	"fmt"

	apikeyauth "github.com/anshulgoel27/krakend-apikey-auth"
	apikeyauthgin "github.com/anshulgoel27/krakend-apikey-auth/gin"
	ipfilter "github.com/anshulgoel27/krakend-ipfilter"
	lognats "github.com/anshulgoel27/krakend-lognats"
	krakendrate "github.com/anshulgoel27/krakend-ratelimit/v3"
	ratelimit "github.com/anshulgoel27/krakend-ratelimit/v3/router/gin"
	botdetector "github.com/krakendio/krakend-botdetector/v2/gin"
	jose "github.com/krakendio/krakend-jose/v2"
	lua "github.com/krakendio/krakend-lua/v2/router/gin"
	metrics "github.com/krakendio/krakend-metrics/v2/gin"
	opencensus "github.com/krakendio/krakend-opencensus/v2/router/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	router "github.com/luraproject/lura/v2/router/gin"
	"github.com/luraproject/lura/v2/transport/http/server"

	"github.com/gin-gonic/gin"
)

// NewHandlerFactory returns a HandlerFactory with a rate-limit and a metrics collector middleware injected
func NewHandlerFactory(ctx context.Context, logger logging.Logger,
	metricCollector *metrics.Metrics,
	rejecter jose.RejecterFactory,
	apiKeyAuthManager *apikeyauth.AuthKeyLookupManager,
	redisConfig *krakendrate.RedisConfig) router.HandlerFactory {
	handlerFactory := router.CustomErrorEndpointHandler(logger, server.DefaultToHTTPError)
	handlerFactory = lognats.NewHandlerFactory(ctx, handlerFactory, logger)
	handlerFactory = ratelimit.NewRateLimiterMw(logger, redisConfig, handlerFactory)
	handlerFactory = ratelimit.NewTriredRateLimiterMw(logger, redisConfig, handlerFactory)
	handlerFactory = lua.HandlerFactory(logger, handlerFactory)
	//handlerFactory = ginjose.HandlerFactory(handlerFactory, logger, rejecter)
	handlerFactory = metricCollector.NewHTTPHandlerFactory(handlerFactory)
	handlerFactory = opencensus.New(handlerFactory)
	handlerFactory = botdetector.New(handlerFactory, logger)
	if apiKeyAuthManager != nil {
		handlerFactory = apikeyauthgin.NewHandlerFactory(apiKeyAuthManager, handlerFactory, logger, rejecter)
	}
	handlerFactory = ipfilter.HandlerFactory(handlerFactory, logger)

	return func(cfg *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		logger.Debug(fmt.Sprintf("[ENDPOINT: %s] Building the http handler", cfg.Endpoint))
		return handlerFactory(cfg, p)
	}
}

type handlerFactory struct{}

func (handlerFactory) NewHandlerFactory(ctx context.Context,
	l logging.Logger,
	m *metrics.Metrics,
	r jose.RejecterFactory,
	apiKeyAuthManager *apikeyauth.AuthKeyLookupManager,
	redisConfig *krakendrate.RedisConfig) router.HandlerFactory {
	return NewHandlerFactory(ctx, l, m, r, apiKeyAuthManager, redisConfig)
}
