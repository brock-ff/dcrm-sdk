FROM ubuntu:latest

# install system deps
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y git make wget golang

# install go
# RUN wget -c https://dl.google.com/go/go1.15.8.linux-amd64.tar.gz -O - | tar -xz -C /usr/local
# ENV GOROOT /usr/lib/go
# ENV GOPATH /go
# ENV PATH /go/bin:$PATH
RUN go version

WORKDIR /src
COPY . .
RUN make

CMD [ "/src/bin/cmd/gdcrm", "help" ]
