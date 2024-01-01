FROM golang:1.18-alpine

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go ./
COPY tscanner ./tscanner

RUN CGO_ENABLED=0 GOOS=linux go build -o Terrapin-Scanner

ENTRYPOINT [ "/app/Terrapin-Scanner" ]