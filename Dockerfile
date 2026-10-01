# syntax = docker/dockerfile:1.7

FROM golang:1.24-alpine AS build

WORKDIR /src

COPY ocproxy/go* ./

RUN go mod download

COPY ocproxy/ .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/ocproxy main.go

FROM alpine:latest

COPY --from=build /out/ocproxy /ocproxy

USER nobody

ENTRYPOINT ["/ocproxy"]
