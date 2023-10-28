#!/bin/bash
echo LOCALIP:$LOCAL_IP
echo printenv
echo "starting install"
set -e
#exit shell script if last command failed
function detectError(){
    if [ $? -ne 0 ];then
        exit 1
    fi
}
#clean up
set +e
sudo docker rm -f ory-hydra
sudo docker rm -f hydra-postgres
set -e
#set up and run database for hydra
sudo docker compose -p identity-provider-project -f docker-compose-postgres-hydra.yaml up -d
echo sleep 5 seconds for waiting brand-new database to run
sleep 5
#set environments for developmennt
export HydraDSN=postgres://hydra:secret@$LOCAL_IP:5420/hydra?sslmode=disable \
export IDPDSN=postgres://hydra:secret@$LOCAL_IP:5420/idp?sslmode=disable \
export HydraPublicAddr=https://$LOCAL_IP:8010 \
export IdentityProviderAddr=https://$LOCAL_IP:11109 \
export SECRETS_SYSTEM_HYDRA=JWyB4HySJjACDuktN98Vv1R4GyOPfqta
echo creating network:hydranetwork
if sudo docker network  ls|grep hydranetwork;then
echo the network aready exists
else
sudo docker network create hydranetwork
fi
echo "running migrations"
sudo docker run -it --rm \
  --network hydranetwork \
  oryd/hydra:v1.0.8 \
  migrate sql --yes $HydraDSN
echo "finished migrations"
#run the hydra server
sudo docker run \
  --name ory-hydra \
  --network hydranetwork \
  --detach \
  --restart=always \
  -p 8010:4444 \
  -p 8009:4445 \
  -e SECRETS_SYSTEM=$SECRETS_SYSTEM_HYDRA \
  -e DSN=$HydraDSN \
  -e URLS_SELF_ISSUER=$HydraPublicAddr \
  -e URLS_CONSENT=$IdentityProviderAddr/consent \
  -e URLS_LOGIN=$IdentityProviderAddr/login \
  -e URLS_LOGOUT=$IdentityProviderAddr/logout \
  -e URLS_POST_LOGOUT_REDIRECT=$IdentityProviderAddr/ \
  oryd/hydra:v1.0.8 serve all 

#create database idp
sudo docker exec hydra-db psql -U hydra -c "CREATE DATABASE idp"|| true
#migrate idp database
./docker/build.sh
sudo docker run --rm idp migrate sql --conn_info=$IDPDSN||true
#generate TLS certificate  
openssl req -newkey rsa:4096 \
-x509 \
-sha256 \
-days 365 \
-nodes \
-out .cache/localhost.crt \
-keyout .cache/localhost.key \
-subj "/C=CH/ST=GUANGDNG/L=SHENZHEN/O=SECURITY/OU=IT DEPARTMENT/CN=$LOCAL_IP:8010"
#run docker container for idp
