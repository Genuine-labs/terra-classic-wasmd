package v1

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/CosmWasm/wasmd/x/wasm/types"
)

// AddToSecondIndexFn creates a secondary index entry for the creator fo the contract
type Migrate func(ctx sdk.Context) error

// Keeper abstract keeper
type wasmKeeper interface {
	IterateContractInfo(ctx sdk.Context, cb func(sdk.AccAddress, types.ContractInfo) bool)
}

// Migrator is a struct for handling in-place store migrations.
type Migrator struct {
	keeper  wasmKeeper
	migrate Migrate
}

// NewMigrator returns a new Migrator.
func NewMigrator(k wasmKeeper, fn Migrate) Migrator {
	return Migrator{keeper: k, migrate: fn}
}

// Migrate1to2 migrates from version 1 to 2.
func (m Migrator) Migrate1to2(ctx sdk.Context) error {
	return m.migrate(ctx)
}
