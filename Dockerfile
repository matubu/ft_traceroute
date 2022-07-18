FROM alpine

WORKDIR /data

RUN ["apk", "add", "make", "gcc", "libc-dev"]