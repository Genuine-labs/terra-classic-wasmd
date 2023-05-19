package keeper

import (
	"github.com/cosmos/cosmos-sdk/store/prefix"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/CosmWasm/wasmd/x/wasm/types"
	legacytypes "github.com/CosmWasm/wasmd/x/wasm/types/legacy"
)

// SetContractInfo stores ContractInfo for the given contractAddress
func (k Keeper) SetLegacyContractInfo(ctx sdk.Context, contractAddress sdk.AccAddress, codeInfo legacytypes.ContractInfo) {
	store := ctx.KVStore(k.storeKey)
	b := k.cdc.MustMarshal(&codeInfo)
	store.Set(types.GetContractAddressKey(contractAddress), b)
}

// IterateLegacyContractInfo iterates all contract infos in legacy terra wasm store
func (k Keeper) IterateLegacyContractInfo(ctx sdk.Context, cb func(legacytypes.ContractInfo) bool) {
	prefixStore := prefix.NewStore(ctx.KVStore(k.storeKey), legacytypes.ContractInfoKey)
	iter := prefixStore.Iterator(nil, nil)
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		var contract legacytypes.ContractInfo
		k.cdc.MustUnmarshal(iter.Value(), &contract)
		// cb returns true to stop early
		if cb(contract) {
			break
		}
	}
}

// IterateLegacyContractInfo iterates all code infos in legacy terra wasm store
func (k Keeper) IterateLegacyCodeInfo(ctx sdk.Context, cb func(legacytypes.CodeInfo) bool) {
	prefixStore := prefix.NewStore(ctx.KVStore(k.storeKey), legacytypes.CodeKey)
	iter := prefixStore.Iterator(nil, nil)
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		var code legacytypes.CodeInfo
		k.cdc.MustUnmarshal(iter.Value(), &code)
		// cb returns true to stop early
		if cb(code) {
			return
		}
	}
}
