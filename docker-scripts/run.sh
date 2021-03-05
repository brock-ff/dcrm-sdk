# pass NAME & DARGS as env variables
# required: NAME unique container name
# optional: DARGS docker args
docker run -v "$PWD/data":"/data" -w "/data" -it $DARGS --network host --name $NAME dcrm "$@"
