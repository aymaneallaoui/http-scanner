FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o http-scanner .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/http-scanner .
COPY --from=builder /app/configs ./configs
ENTRYPOINT ["./http-scanner"]
