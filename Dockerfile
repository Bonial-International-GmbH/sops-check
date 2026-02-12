FROM golang:1.26-alpine AS builder

WORKDIR /src

RUN apk --update --no-cache add git make

ENV CGO_ENABLED=0

COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile

RUN go mod download

COPY *.go ./
COPY internal internal/

RUN make build

FROM alpine:3.23

RUN apk --update --no-cache add ca-certificates

COPY --from=builder /src/sops-check /sops-check

USER nobody

ENTRYPOINT ["/sops-check"]
