package v1_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"

	"github.com/CosmWasm/wasmd/x/wasm/keeper"
	types "github.com/CosmWasm/wasmd/x/wasm/types"
	legacytypes "github.com/CosmWasm/wasmd/x/wasm/types/legacy"
)

// integration testing of smart contract
func TestMigrate1To2(t *testing.T) {
	const AvailableCapabilities = "iterator,staking,stargate,cosmwasm_1_1"
	ctx, keepers := keeper.CreateTestInput(t, false, AvailableCapabilities)
	wasmKeeper := keepers.WasmKeeper

	deposit := sdk.NewCoins(sdk.NewInt64Coin("denom", 100000))
	creator := sdk.AccAddress(bytes.Repeat([]byte{1}, address.Len))
	keepers.Faucet.Fund(ctx, creator, deposit...)
	newLegacyContract(wasmKeeper, ctx, creator, t)

	// migrator
	migrator := keeper.NewMigrator(*wasmKeeper, nil)
	err := migrator.Migrate1to2(ctx)
	require.NoError(t, err)

	// label must equal address and no empty admin
	wasmKeeper.IterateContractInfo(ctx, func(addr sdk.AccAddress, info types.ContractInfo) bool {
		require.Equal(t, info.Label, addr.String())
		require.NotEqual(t, info.Admin, "")
		return false
	})
}

func newLegacyContract(wasmkeeper *keeper.Keeper, ctx sdk.Context, creator sdk.AccAddress, t *testing.T) legacytypes.ContractInfo {
	t.Helper()

	contractAddress := keeper.RandomAccountAddress(t)
	contract := legacytypes.NewContractInfo(1, contractAddress, creator, creator, []byte("init"))
	wasmkeeper.SetLegacyContractInfo(ctx, contractAddress, contract)

	contractAddress = keeper.RandomAccountAddress(t)
	contract = legacytypes.NewContractInfo(2, contractAddress, creator, sdk.AccAddress{}, []byte("init"))
	wasmkeeper.SetLegacyContractInfo(ctx, contractAddress, contract)

	return contract
}
