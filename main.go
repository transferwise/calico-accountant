package main

import (
	"flag"
	"os"
	"strconv"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"

	"github.com/monzo/calico-accountant/metrics"
	"github.com/monzo/calico-accountant/watch"
)

func main() {
	loggerCfg := zap.NewProductionConfig()
	loggerCfg.EncoderConfig.TimeKey = "timestamp"
	loggerCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	level, ok := os.LookupEnv("LOG_LEVEL")
	if !ok {
		level = "INFO"
	}
	loggerCfg.Level.UnmarshalText([]byte(level))
	logger, err := loggerCfg.Build()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}
	zap.ReplaceGlobals(logger)
	defer logger.Sync()

	flag.Parse()

	port, ok := os.LookupEnv("METRICS_SERVER_PORT")
	if !ok {
		port = "9009"
	}

	var minCounter int
	minCounterStr, ok := os.LookupEnv("MINIMUM_COUNTER")
	if ok {
		var err error
		minCounter, err = strconv.Atoi(minCounterStr)
		if err != nil {
			zap.L().Fatal("Failed to parse minimum counter", zap.String("error", err.Error()))
		}
	}

	cw, err := watch.New()
	if err != nil {
		zap.L().Fatal("Error setting up calico watcher", zap.String("error", err.Error()))
	}

	metrics.Run(cw, port, minCounter)
}
