#------------------------------------------------------------------
FROM golang:1.17-alpine as builder

# Update alpine.
RUN apk update && apk upgrade

# Install alpine dependencies.
RUN apk --no-cache --update add build-base bash

# Create and change to the 'service' directory.
WORKDIR /service

# Install project dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Copy and test code.
COPY . .
RUN make test

# Build application binary.
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -v -o bin/main

#-------------------------------------------------------------------
FROM alpine:3

# Create and change to the the 'service' directory.
WORKDIR /service

# Copy the files to the production image from the builder stage.
COPY --from=builder /service/bin /service/

# Run the web service on container startup.
CMD ["/service/main"]

#-------------------------------------------------------------------
