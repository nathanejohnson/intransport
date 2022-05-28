FROM golang:1.18-alpine

COPY . /root

WORKDIR /root

ENV CGO_ENABLED=0
RUN go test -v
