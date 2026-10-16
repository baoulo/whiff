module github.com/example/harbour

go 1.23

toolchain go1.23.2

require (
	github.com/go-chi/chi/v5 v5.1.0
	golang.org/x/sync v0.8.0
	github.com/stretchr/testify v1.9.0 // indirect
)

require github.com/google/uuid v1.6.0

replace github.com/example/model => ../model
