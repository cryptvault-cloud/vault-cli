module github.com/cryptvault-cloud/vault-cli

go 1.25.1

require (
	github.com/cryptvault-cloud/api v0.2.3
	github.com/cryptvault-cloud/helper v0.2.0
	github.com/urfave/cli/v3 v3.6.2
	github.com/vektah/gqlparser/v2 v2.5.23
	go.uber.org/zap v1.26.0
)

require (
	github.com/Khan/genqlient v0.8.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.uber.org/goleak v1.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
)

// replace github.com/cryptvault-cloud/api v0.0.5 => ../api
