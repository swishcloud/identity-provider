#/bin/sh
if [ -z $REPO ]
then
REPO='idp'
fi
TAG=`git log| grep '(?<=^commit ).+' -m1 -oP`
echo 'image tag:'$TAG

#some variables
export PROGRAM_NAME='idp'

#build the docker image
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./.dist/$PROGRAM_NAME
#copy files need for the image to the dist folder
cp templates  ./.dist -r
cp static  ./.dist -r
cp migrations  ./.dist -r
#buiding
docker build --tag $REPO:$TAG --tag $REPO -f docker/dockerfile ./.dist