FROM golang:1.18-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go ./
COPY tscanner ./tscanner

RUN CGO_ENABLED=0 GOOS=linux go build -o Terrapin-Scanner

FROM scratch

COPY --from=builder /app/Terrapin-Scanner /app/Terrapin-Scanner

USER nobody:nobody

ENTRYPOINT [ "/app/Terrapin-Scanner" ]
