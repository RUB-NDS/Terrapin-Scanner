FROM golang:1.18-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go ./
COPY tscanner ./tscanner

RUN CGO_ENABLED=0 GOOS=linux go build -o Terrapin-Scanner
RUN ["echo", "nobody:*:65534:65534:nobody:/_nonexistent:/bin/false", ">", "/etc/passwd"]
FROM scratch

COPY --from=builder /app/Terrapin-Scanner /app/Terrapin-Scanner
COPY --from=builder /etc/passwd /etc/passwd
USER nobody

ENTRYPOINT [ "/app/Terrapin-Scanner" ]
