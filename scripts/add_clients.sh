#!/bin/sh
#set environments for develoption
export GOBLOGAddr=http://$LOCAL_IP:8080 
export IDENTITY_PROVIDER_ADDDR=https://$LOCAL_IP:11109
export FILESYNC_WEB_ADDDR=https://$LOCAL_IP:2002
export HydraAdminAddr=https://$LOCAL_IP:8009 
#create client GOBLOG
sudo docker run --rm -it \
 -e HYDRA_ADMIN_URL=$HydraAdminAddr \
 oryd/hydra:v1.0.8 \
 clients delete GOBLOG --skip-tls-verify 

sudo docker run --rm -it \
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
sudo docker run --rm -it \
 -e HYDRA_ADMIN_URL=$HydraAdminAddr \
 oryd/hydra:v1.0.8 \
 clients delete --skip-tls-verify \
 IDENTITY_PROVIDER

sudo docker run --rm -it \
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

#create client FILESYNC_WEB
sudo docker run --rm -it \
 -e HYDRA_ADMIN_URL=$HydraAdminAddr \
 oryd/hydra:v1.0.8 \
 clients delete FILESYNC_WEB --skip-tls-verify 

sudo docker run --rm -it \
 -e HYDRA_ADMIN_URL=$HydraAdminAddr \
 oryd/hydra:v1.0.8 \
 clients create --skip-tls-verify \
 --id FILESYNC_WEB \
 --secret FILESYNC_WEB_SECRET \
 --grant-types authorization_code,refresh_token \
 --response-types token,code,id_token \
 --scope openid,offline,profile \
 --callbacks $FILESYNC_WEB_ADDDR/login-callback \
 --post-logout-callbacks $FILESYNC_WEB_ADDDR \
 --token-endpoint-auth-method client_secret_post
#create client FILESYNC_MOBILE
sudo docker run --rm -it \
 -e HYDRA_ADMIN_URL=$HydraAdminAddr \
 oryd/hydra:v1.0.8 \
 clients delete FILESYNC_MOBILE --skip-tls-verify 
 
sudo docker run --rm -it \
 -e HYDRA_ADMIN_URL=$HydraAdminAddr \
 oryd/hydra:v1.0.8 \
 clients create --skip-tls-verify \
 --id FILESYNC_MOBILE \
 --grant-types authorization_code,refresh_token \
 --response-types token,code,id_token \
 --scope openid,offline,profile \
 --callbacks com.example.app:/logincallback,$IDENTITY_PROVIDER_ADDDR/.approvalnativeapp \
 --token-endpoint-auth-method none
 #--callbacks $IDENTITY_PROVIDER_ADDDR/.approvalnativeapp \
sudo docker run --rm -it  -e HYDRA_ADMIN_URL=$HydraAdminAddr  oryd/hydra:v1.0.8 clients --skip-tls-verify list
