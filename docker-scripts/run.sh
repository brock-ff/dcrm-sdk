# pass NAME as an ENV variable
docker run -v "$PWD/data":"/data" -w "/data" -it $DARGS --name $NAME dcrm "$@"
