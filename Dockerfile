FROM ubuntu:latest

# install system deps
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y git make wget golang

WORKDIR /src
COPY . .
RUN make

CMD [ "/src/bin/cmd/gdcrm", "help" ]
