FROM registry.gitlab.casa-systems.com/platform/sdk as builder

ARG GIT_COMMIT=unknown
LABEL git-commit=$GIT_COMMIT

WORKDIR /opt/casa/sctpmgr
COPY . .

RUN axyom deps

RUN CGO_ENABLED=1 GOOS=linux go build -mod=vendor -a -ldflags '-extldflags "-static"'

FROM alpine:latest
WORKDIR /opt/casa/

