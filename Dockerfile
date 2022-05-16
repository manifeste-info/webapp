FROM devopsworks/golang-upx:1.17 AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

ARG VERSION=n/a \
    BUILD_DATE=n/a

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN go build \
        -ldflags="-X 'main.Version=${VERSION}' -X 'main.BuildDate=${BUILD_DATE}'" \
        -o manifeste \
        .
    # && strip manifeste \
    # && /usr/local/bin/upx -9 manifeste

ENTRYPOINT [ "/build/manifeste", "migrate:up" ]