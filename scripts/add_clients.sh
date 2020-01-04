#!/bin/sh
#set environments for develoption
export GOBLOGAddr=http://localhost:8080 
export IDENTITY_PROVIDER_ADDDR=https://localhost:11109
export HydraAdminAddr=https://192.168.100.8:8009 
#create client GOBLOG
docker run --rm -it \
 -e HYDRA_ADMIN_URL=$HydraAdminAddr \
 oryd/hydra:v1.0.8 \
 clients create --skip-tls-verify \
 --id GOBLOG \
 --secret GOBLOGSECRET \
 --grant-types authorization_code,refresh_token \
 --response-types token,code,id_token \
 --scope openid,offline,profile \
 --callbacks $GOBLOGAddr/callback \
 --post-logout-callbacks $GOBLOGAddr/login \
 --token-endpoint-auth-method client_secret_post

#create client IDENTITY_PROVIDER
docker run --rm -it \
 -e HYDRA_ADMIN_URL=$HydraAdminAddr \
 oryd/hydra:v1.0.8 \
 clients create --skip-tls-verify \
 --id IDENTITY_PROVIDER \
 --secret IDENTITY_PROVIDER_SECRET \
 --grant-types authorization_code,refresh_token \
 --response-types token,code,id_token \
 --scope openid,offline,profile \
 --callbacks $IDENTITY_PROVIDER_ADDDR/login-callback \
 --post-logout-callbacks $IDENTITY_PROVIDER_ADDDR/login \
 --token-endpoint-auth-method client_secret_post
