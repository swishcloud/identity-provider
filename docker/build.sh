#/bin/sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./.dist/app
COPY templates  ./.dist
COPY static  ./.dist
docker build --tag idp:1.0 -f docker/dockerfile ./.dist