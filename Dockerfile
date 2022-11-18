FROM golang:1.19.3 AS builder
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64
RUN git config --global url."https://Security365:cwno7y7q6w5qagijwrzggjluashveoxbq3xlidnzu72332oiga3q@dev.azure.com/Security365/Security365Common/".insteadOf "https://dev.azure.com/Security365/Security365Common/"
RUN go env -w GOPRIVATE=dev.azure.com/Security365
WORKDIR /build
COPY . ./

RUN "go install github.com/jstemmer/go-junit-report/v2@latest"
RUN mkdir -p /reports
RUN "go test ./... -v 2>&1 ./... | go-junit-report -set-exit-code > /reports/result.xml"

RUN go build -o socamauthproxy .
WORKDIR /dist
RUN cp /build/socamauthproxy .
FROM busybox
COPY --from=builder /dist/socamauthproxy .
ENTRYPOINT ["/socamauthproxy"]