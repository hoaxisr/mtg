package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/9seconds/mtg/v2/internal/config"
	"github.com/9seconds/mtg/v2/internal/utils"
	"github.com/9seconds/mtg/v2/mtglib"
	"github.com/9seconds/mtg/v2/mtglib/web"
)

const (
	webReadHeaderTimeout = 10 * time.Second
	webIdleTimeout       = 75 * time.Second
	webMaxHeaderBytes    = 16 << 10
)

// makeWebHandler builds a WEB proxy handler from the config. It returns nil,
// nil if the WEB proxy is disabled.
func makeWebHandler(conf *config.Config, proxy *mtglib.Proxy, logger mtglib.Logger) (*web.Handler, error) {
	if !conf.Web.Enabled.Get(false) {
		return nil, nil //nolint: nilnil
	}

	var (
		public http.Handler
		err    error
	)

	if upstream := conf.Web.PublicUpstream.Get(nil); upstream != nil {
		public, err = web.NewPublicUpstream(upstream)
	} else {
		public, err = web.NewPublicDir(conf.Web.PublicDir.Get(""))
	}

	if err != nil {
		return nil, fmt.Errorf("cannot build web public site: %w", err)
	}

	handler, err := web.NewHandler(web.Options{
		Hostname:       conf.Web.Hostname.Get(""),
		Profiles:       []web.Profile{{Index: 0, Secret: conf.Secret}},
		Serve:          proxy.ServeWebConn,
		Public:         public,
		TrustedProxies: conf.GetWebTrustedProxies(),
		TokenKey:       conf.Web.TokenKey.Get(nil),
		Limits:         conf.GetWebLimits(),
		Timeouts:       conf.GetWebTimeouts(),
		Logger:         logger.Named("web"),
	})
	if err != nil {
		return nil, fmt.Errorf("cannot build web handler: %w", err)
	}

	return handler, nil
}

// serveWeb starts serving the WEB proxy on its own listener. It returns a nil
// shutdown if handler is nil. The returned shutdown is idempotent: it shuts
// the handler down first (releasing parked long polls), then the server.
func serveWeb(ctx context.Context,
	conf *config.Config,
	handler *web.Handler,
	logger mtglib.Logger,
) (func(), error) {
	if handler == nil {
		return nil, nil
	}

	listener, err := utils.NewListener(conf.Web.BindTo.Get(""), 0)
	if err != nil {
		return nil, fmt.Errorf("cannot start web proxy: %w", err)
	}

	return serveWebListener(ctx, conf, handler, listener, logger), nil
}

func serveWebListener(ctx context.Context,
	conf *config.Config,
	handler *web.Handler,
	listener net.Listener,
	logger mtglib.Logger,
) func() {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: webReadHeaderTimeout,
		IdleTimeout:       webIdleTimeout,
		MaxHeaderBytes:    webMaxHeaderBytes,
		// OPTIONS * reaches the handler, and so the public site, instead of
		// a built-in answer that only a Go server gives.
		DisableGeneralOptionsHandler: true,
	}

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.WarningError("web proxy server has stopped", err)
		}
	}()

	once := &sync.Once{}

	// The handler is shut down first: it closes every session, which
	// releases parked /down long polls, and answers authenticated requests
	// with 404 from then on. Only then does server.Shutdown wait for active
	// requests, which no longer include a long poll held for up to
	// web.timeouts.long-poll. Both share one web.timeouts.shutdown budget.
	return func() {
		once.Do(func() {
			// The root context is already done when shutdown is called, so
			// only its values are kept.
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx),
				conf.GetWebTimeouts().Shutdown)
			defer cancel()

			if err := handler.Shutdown(shutdownCtx); err != nil {
				logger.WarningError("cannot shutdown web proxy handler", err)
			}

			if err := server.Shutdown(shutdownCtx); err != nil {
				logger.WarningError("cannot shutdown web proxy server", err)
			}
		})
	}
}
