FROM golang:1.13-alpine3.10

COPY . /root

WORKDIR /root

RUN apk --no-cache add gcc && apk --no-cache add musl-dev && go test -v
