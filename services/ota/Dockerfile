FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY services/ota ./services/ota
RUN CGO_ENABLED=0 go build -trimpath -o /out/ota ./services/ota/cmd/ota

FROM scratch
COPY --from=build /out/ota /ota
ENTRYPOINT ["/ota"]
