#/bin/sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./.dist/app
cp templates  ./.dist -r
cp static  ./.dist -r
docker build --tag $IMAGE_TAG -f docker/dockerfile ./.dist