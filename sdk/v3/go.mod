// Isolated module for the generated v3 Go SDK (typed cross-service models).
// Kept separate from kielo-shared's main module so the codegen runtime
// dependency (and its transitive bumps) never ripples into every service.
// Consumers opt in via go.work + an explicit import.
module github.com/team-kielo-app/kielo-shared/sdk/v3

go 1.25.0

require github.com/oapi-codegen/runtime v1.4.1

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
)
