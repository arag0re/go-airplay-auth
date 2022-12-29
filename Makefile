run:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go run ./main/main.go
build:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -o cmd/airplay ./main/main.go;chmod +x cmd/airplay
