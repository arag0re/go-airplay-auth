run:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go run ./internal/main/main.go
build:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -o cmd/auth ./internal/main/main.go;chmod +x cmd/auth
