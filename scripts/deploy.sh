#!/bin/sh
docker push $IMAGE_TAG
sshpass -p $SSH_DEPLOY_PASSWORD $SSH_CMMAND $TRAVIS_COMMIT
if [ $? -ne 0 ]; then
    echo "deploy failed"
    exit 1
else
    echo "-----------------------------"
    echo "deploy completed successfully"
    echo "-----------------------------"
fi