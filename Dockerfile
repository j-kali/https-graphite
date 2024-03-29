FROM golang:1.18.3-alpine3.16 as build

RUN apk add make git bash
COPY . /go/src/project/
WORKDIR /go/src/project/
RUN make

FROM alpine
COPY --from=build /go/src/project/https-graphite /bin/https-graphite
RUN apk add openssl
ENTRYPOINT ["/bin/https-graphite"]
