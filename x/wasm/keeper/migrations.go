package keeper

import (
	"fmt"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/CosmWasm/wasmd/x/wasm/exported"
	v1 "github.com/CosmWasm/wasmd/x/wasm/migrations/v1"
	v2 "github.com/CosmWasm/wasmd/x/wasm/migrations/v2"
	v3 "github.com/CosmWasm/wasmd/x/wasm/migrations/v3"
	"github.com/CosmWasm/wasmd/x/wasm/types"
	legacytypes "github.com/CosmWasm/wasmd/x/wasm/types/legacy"
)

// Migrator is a struct for handling in-place store migrations.
type Migrator struct {
	highestCodeID  uint64
	keeper         Keeper
	legacySubspace exported.Subspace
}

// NewMigrator returns a new Migrator.
func NewMigrator(keeper Keeper, legacySubspace exported.Subspace) Migrator {
	return Migrator{keeper: keeper, legacySubspace: legacySubspace}
}

// Migrate1to2 migrates from version 1 to 2.
func (m Migrator) Migrate1to2(ctx sdk.Context) error {
	return v1.NewMigrator(m.keeper, m.TerraMigrate1to2).Migrate1to2(ctx)
}

// Migrate2to3 migrates the x/wasm module state from the consensus
// version 2 to version 3.
func (m Migrator) Migrate2to3(ctx sdk.Context) error {
	return v2.MigrateStore(ctx, m.keeper.storeKey, m.legacySubspace, m.keeper.cdc)
}

// Migrate3to4 migrates the x/wasm module state from the consensus
// version 3 to version 4.
func (m Migrator) Migrate3to4(ctx sdk.Context) error {
	return v3.NewMigrator(m.keeper, m.keeper.storeCodeInfo).Migrate3to4(ctx, m.keeper.storeKey, m.keeper.cdc)
}

// of terra fork
func (m Migrator) TerraMigrate1to2(ctx sdk.Context) error {
	ctx.Logger().Info("### Setting Default wasmd parameters ###")
	m.setWasmDefaultParams(ctx)

	ctx.Logger().Info("### Migrating Code Info ###")
	m.keeper.IterateLegacyCodeInfo(ctx, func(codeInfo legacytypes.CodeInfo) bool {
		creatorAddr := sdk.MustAccAddressFromBech32(codeInfo.Creator)
		err := m.migrateCodeFromLegacy(ctx, creatorAddr, codeInfo.CodeID, codeInfo.CodeHash)
		if err != nil {
			m.keeper.Logger(ctx).Error("Was not able to store legacy code ID")
		}
		return false
	})

	// TODO
	m.keeper.Logger(ctx).Info("#### Migrating Contract Info ###")
	m.keeper.IterateLegacyContractInfo(ctx, func(contractInfo legacytypes.ContractInfo) bool {
		contractAddress := sdk.MustAccAddressFromBech32(contractInfo.Address)

		ctx.Logger().Info(fmt.Sprintf("Migrating contract address: %s", contractAddress.String()))

		creatorAddr := sdk.MustAccAddressFromBech32(contractInfo.Creator)

		newContract := m.migrateAbsoluteTx(ctx, contractInfo)

		// add to contract history
		history := newContract.InitialHistory(contractInfo.InitMsg)
		m.keeper.appendToContractHistory(ctx, contractAddress, history)
		// add to contract creator secondary index
		m.keeper.addToContractCreatorSecondaryIndex(ctx, creatorAddr, newContract.Created, contractAddress)
		// add to contract code secondary index
		m.keeper.addToContractCodeSecondaryIndex(ctx, contractAddress, history)

		return false
	})
	return nil
}

func (m Migrator) setLastCodeID(ctx sdk.Context, id uint64) {
	store := ctx.KVStore(m.keeper.storeKey)
	bz := sdk.Uint64ToBigEndian(id)
	store.Set(types.KeySequenceCodeID, bz)
}

// setWasmParams sets the wasm parameters to the default in wasmd
// in terra classic we don't have these params - so we set them
// to default
func (m Migrator) setWasmDefaultParams(ctx sdk.Context) {
	params := types.DefaultParams()
	m.keeper.SetParams(ctx, params)
}

// Migrate AbsoluteTxPosition
// I am afraid that setting all contracts at one absolute tx position will break query
func (m Migrator) migrateAbsoluteTx(ctx sdk.Context, contractInfo legacytypes.ContractInfo) types.ContractInfo {
	createdAt := types.NewAbsoluteTxPosition(ctx)

	creatorAddr := sdk.MustAccAddressFromBech32(contractInfo.Creator)
	// admin field can be null in legacy contract
	// admin will be set to creator if admin is ""
	var admin sdk.AccAddress
	if contractInfo.Admin != "" {
		admin = sdk.MustAccAddressFromBech32(contractInfo.Admin)
	} else {
		admin = sdk.MustAccAddressFromBech32(contractInfo.Creator)
	}
	contractAddr := sdk.MustAccAddressFromBech32(contractInfo.Address)
	label := contractAddr.String()

	newContract := types.NewContractInfo(contractInfo.CodeID, creatorAddr, admin, label, createdAt)
	m.keeper.storeContractInfo(ctx, contractAddr, &newContract)

	return newContract
}

// createCodeFromLegacy - this function migrates the CodeInfo store
func (m Migrator) migrateCodeFromLegacy(ctx sdk.Context, creator sdk.AccAddress, codeID uint64, hash []byte) error {
	if creator == nil {
		return sdkerrors.ErrInvalidAddress.Wrap("creator cannot be nil")
	}

	// on terra wasm there was no access config
	// this returns default AccessConfig
	defaultAccessConfig := m.keeper.getInstantiateAccessConfig(ctx).With(creator)

	// unsure whether we need this?
	//_, err := m.keeper.wasmVM.AnalyzeCode(hash)
	//if err != nil {
	//	return sdkerrors.Wrap(types.ErrCreateFailed, err.Error())
	//}

	// can we expect the code IDs to come in order from the
	// iterator? Dunno - that's why we need this mechanism to
	// identify the last ID
	if codeID > m.highestCodeID {
		m.highestCodeID = codeID
		m.setLastCodeID(ctx, m.highestCodeID)
	}

	// Create wasmd compatible CodeInfo and store it
	m.keeper.Logger(ctx).Info(fmt.Sprintf("codeID = %d", codeID))
	codeInfo := types.NewCodeInfo(hash, creator, defaultAccessConfig)
	m.keeper.storeCodeInfo(ctx, codeID, codeInfo)

	return nil
}
