# syntax = docker/dockerfile:1.7

FROM golang:1.24-alpine AS build

WORKDIR /src

COPY zenproxy/go* ./

RUN go mod download

COPY zenproxy/ .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/zenproxy main.go

FROM alpine:latest

COPY --from=build /out/zenproxy /zenproxy

USER nobody

ENTRYPOINT ["/zenproxy"]
