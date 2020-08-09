from quay.io/jonnrb/go as build-piad
add go.* ./
run go mod download
add . ./
run CGO_ENABLED=0 go get ./cmd/piad

from gcr.io/distroless/static as piad
copy --from=build-piad /go/bin/piad /piad
entrypoint ["/piad"]
