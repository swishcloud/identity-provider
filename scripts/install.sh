#!/bin/bash
echo "starting install"

#exit shell script if last command failed
function detectError(){
    if [ $? -ne 0 ];then
        exit 1
    fi
}
#clean up
docker rm -f ory-hydra
docker rm -f hydra-postgres
#set up and run database for hydra
docker run \
 --name hydra-postgres \
 --rm \
 -p 5420:5432 \
 -e POSTGRES_USER=hydra \
 -e POSTGRES_PASSWORD=secret  \
 -e POSTGRES_DB=hydra \
 -d \
 postgres
echo sleep 5 seconds for waiting brand-new database to run
sleep 5
#set environments for develoption
export HydraDSN=postgres://hydra:secret@192.168.100.8:5420/hydra?sslmode=disable \
export IDPDSN=postgres://hydra:secret@192.168.100.8:5420/idp?sslmode=disable \
export HydraPublicAddr=http://127.0.0.1:8010 \
export IdentityProviderAddr=http://127.0.0.1:11109 \
export SECRETS_SYSTEM_HYDRA=JWyB4HySJjACDuktN98Vv1R4GyOPfqta

#running migrations
docker run -it --rm \
  --network hydranetwork \
  oryd/hydra:v1.0.8 \
  migrate sql --yes $HydraDSN
#run the hydra server
docker run \
  --name ory-hydra \
  --network hydranetwork \
  --rm \
  --detach \
  -p 8010:4444 \
  -p 8009:4445 \
  -e SECRETS_SYSTEM=$SECRETS_SYSTEM_HYDRA \
  -e DSN=$HydraDSN \
  -e URLS_SELF_ISSUER=$HydraPublicAddr \
  -e URLS_CONSENT=$IdentityProviderAddr/consent \
  -e URLS_LOGIN=$IdentityProviderAddr/login \
  -e URLS_LOGIN=$IdentityProviderAddr/login \
  -e URLS_LOGOUT=$IdentityProviderAddr/logout \
  -e URLS_POST_LOGOUT_REDIRECT=$IdentityProviderAddr/ \
  oryd/hydra:v1.0.8 serve all --dangerous-force-http
#create database idp
docker exec hydra-postgres psql -U hydra -c "CREATE DATABASE idp"
  #migrate idp database
  export IMAGE_TAG=dev
  ./docker/build.sh
  docker run --rm $IMAGE_TAG migrate sql --conn_info=$IDPDSN