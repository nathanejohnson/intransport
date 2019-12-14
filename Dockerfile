FROM golang:1.13-alpine3.10

COPY . /root

WORKDIR /root

ENV CGO_ENABLED=0
RUN go test -v
