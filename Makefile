run_linux_arm64:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go run ./internal/main/main.go
run_linux_amd64:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go run ./internal/main/main.go
run_macos_arm64: 
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go run ./internal/main/main.go
run_macos_amd64: 
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go run ./internal/main/main.go
run_win_arm64: 
	CGO_ENABLED=1 GOOS=windows GOARCH=arm64 go run ./internal/main/main.go
run_win_amd64: 
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go run ./internal/main/main.go
build_linux_arm64:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -o cmd/auth ./internal/main/main.go;chmod +x cmd/auth
build_linux_amd64:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o cmd/auth ./internal/main/main.go;chmod +x cmd/auth
build_macos_arm64:
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o cmd/auth ./internal/main/main.go;chmod +x cmd/auth
build_macos_amd64:
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o cmd/auth ./internal/main/main.go;chmod +x cmd/auth
build_win_arm64:
	CGO_ENABLED=1 GOOS=windows GOARCH=arm64 go build -o cmd/auth ./internal/main/main.go;chmod +x cmd/auth
build_win_amd64:
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -o cmd/auth ./internal/main/main.go;chmod +x cmd/auth
