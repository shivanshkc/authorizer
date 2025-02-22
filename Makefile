SHELL=/usr/bin/env bash

# Project specific properties.
application_name        = authorizer
application_binary_name = authorizer

# Container specific properties.
application_image_name     = authorizer
application_container_name = authorizer-1

# Support both podman and docker.
DOCKER=$(shell which podman || which docker || echo 'docker')

# Database DSN for migrations.
database_dsn = "postgres://postgres:dev@localhost:5432/authorizer?sslmode=disable"

# Builds the project.
build:
	@echo "+$@"
	@go build -o bin/$(application_binary_name) cmd/$(application_name)/main.go

# Runs the project after linting and building it anew.
run: tidy build
	@echo "+$@"
	@echo "########### Running the application binary ############"
	@bin/$(application_binary_name)

# Tests the whole project.
test:
	@echo "+$@"
	@CGO_ENABLED=1 go test -race -coverprofile=coverage.out -covermode=atomic ./...

# Runs the "go mod tidy" command.
tidy:
	@echo "+$@"
	@go mod tidy

# Runs golang-ci-lint over the project.
lint:
	@echo "+$@"
	@golangci-lint run ./...

# Builds the docker image for the project.
image:
	@echo "+$@"
	@$(DOCKER) build --network host --file Containerfile --tag $(application_image_name):latest .

# Runs the project container assuming the image is already built.
container:
	@echo "+$@"
	@echo "############### Removing old container ################"
	@$(DOCKER) rm -f $(application_container_name)

	@echo "################ Running new container ################"
	@$(DOCKER) run --name $(application_container_name) --detach --net host --restart unless-stopped \
		--volume $(PWD)/configs/configs.yaml:/etc/$(application_name)/configs.yaml \
		$(application_image_name):latest

# Database migrations.
migrate-up:
	@echo "+$@"
	@migrate -verbose -path db/migrations -database $(database_dsn) up

# Database migrations.
migrate-down:
	@echo "+$@"
	@echo "y" | migrate -verbose -path db/migrations -database $(database_dsn) down