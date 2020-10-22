FROM golang:1.14 as build

WORKDIR /build

COPY . .

# -trimpath remove file system paths from executable
# -ldflags arguments passed to go tool link:
#   -s disable symbol table
#   -w disable DWARF generation
RUN CGO_ENABLED=0 GOOS=linux go install -a -trimpath -ldflags '-extldflags "-s -w -static"' .

FROM gcr.io/distroless/base
COPY --from=build /go/bin/jhove-warc-report-parser /

# api server
EXPOSE 8080/tcp
# prometheus metrics server
EXPOSE 9153/tcp

ENTRYPOINT ["/jhove-warc-report-parser"]
