package utils

import (
	"context"
	"os"
)

func InitState(ctx *context.Context) {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	*ctx = context.WithValue(*ctx, "workingDirectory", dir)
	localCtx := *ctx
	repo := localCtx.Value("ghRepository")
	*ctx = context.WithValue(*ctx, "repositoryDirectory", dir+"/"+repo.(string))
}
