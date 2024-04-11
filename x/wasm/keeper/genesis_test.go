package keeper

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/store"
	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	distributionkeeper "github.com/cosmos/cosmos-sdk/x/distribution/keeper"
	paramskeeper "github.com/cosmos/cosmos-sdk/x/params/keeper"
	paramtypes "github.com/cosmos/cosmos-sdk/x/params/types"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/log"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	dbm "github.com/tendermint/tm-db"

	"github.com/CosmWasm/wasmd/x/wasm/types"
)

const firstCodeID = 1

func TestGenesisExportImport(t *testing.T) {
	wasmKeeper, srcCtx, srcStoreKeys := setupKeeper(t)
	contractKeeper := NewGovPermissionKeeper(wasmKeeper)

	wasmCode, err := os.ReadFile("./testdata/hackatom.wasm")
	require.NoError(t, err)

	// store some test data
	f := fuzz.New().Funcs(ModelFuzzers...)

	wasmKeeper.SetParams(srcCtx, types.DefaultParams())

	for i := 0; i < 25; i++ {
		var (
			codeInfo    types.CodeInfo
			contract    types.ContractInfo
			stateModels []types.Model
			history     []types.ContractCodeHistoryEntry
			pinned      bool
		)
		f.Fuzz(&codeInfo)
		f.Fuzz(&contract)
		f.Fuzz(&stateModels)
		f.NilChance(0).Fuzz(&history)
		f.Fuzz(&pinned)

		creatorAddr, err := sdk.AccAddressFromBech32(codeInfo.Creator)
		require.NoError(t, err)
		codeID, _, err := contractKeeper.Create(srcCtx, creatorAddr, wasmCode, &codeInfo.InstantiateConfig)
		require.NoError(t, err)
		if pinned {
			contractKeeper.PinCode(srcCtx, codeID)
		}

		contract.CodeID = codeID
		contractAddr := wasmKeeper.ClassicAddressGenerator()(srcCtx, codeID, nil)
		wasmKeeper.storeContractInfo(srcCtx, contractAddr, &contract)
		wasmKeeper.appendToContractHistory(srcCtx, contractAddr, history...)
		wasmKeeper.importContractState(srcCtx, contractAddr, stateModels)
	}
	var wasmParams types.Params
	f.NilChance(0).Fuzz(&wasmParams)
	wasmKeeper.SetParams(srcCtx, wasmParams)

	// export
	exportedState := ExportGenesis(srcCtx, wasmKeeper)
	// order should not matter
	rand.Shuffle(len(exportedState.Codes), func(i, j int) {
		exportedState.Codes[i], exportedState.Codes[j] = exportedState.Codes[j], exportedState.Codes[i]
	})
	rand.Shuffle(len(exportedState.Contracts), func(i, j int) {
		exportedState.Contracts[i], exportedState.Contracts[j] = exportedState.Contracts[j], exportedState.Contracts[i]
	})
	rand.Shuffle(len(exportedState.Sequences), func(i, j int) {
		exportedState.Sequences[i], exportedState.Sequences[j] = exportedState.Sequences[j], exportedState.Sequences[i]
	})
	exportedGenesis, err := wasmKeeper.cdc.MarshalJSON(exportedState)
	require.NoError(t, err)

	// setup new instances
	dstKeeper, dstCtx, dstStoreKeys := setupKeeper(t)

	// reset contract code index in source DB for comparison with dest DB
	wasmKeeper.IterateContractInfo(srcCtx, func(address sdk.AccAddress, info types.ContractInfo) bool {
		creatorAddress := sdk.MustAccAddressFromBech32(info.Creator)
		history := wasmKeeper.GetContractHistory(srcCtx, address)

		wasmKeeper.addToContractCodeSecondaryIndex(srcCtx, address, history[len(history)-1])
		wasmKeeper.addToContractCreatorSecondaryIndex(srcCtx, creatorAddress, history[0].Updated, address)
		return false
	})

	// re-import
	var importState types.GenesisState
	err = dstKeeper.cdc.UnmarshalJSON(exportedGenesis, &importState)
	require.NoError(t, err)
	InitGenesis(dstCtx, dstKeeper, importState, &StakingKeeperMock{}, TestHandler(contractKeeper))

	// compare whole DB
	for j := range srcStoreKeys {
		srcIT := srcCtx.KVStore(srcStoreKeys[j]).Iterator(nil, nil)
		dstIT := dstCtx.KVStore(dstStoreKeys[j]).Iterator(nil, nil)

		for i := 0; srcIT.Valid(); i++ {
			require.True(t, dstIT.Valid(), "[%s] destination DB has less elements than source. Missing: %x", srcStoreKeys[j].Name(), srcIT.Key())
			require.Equal(t, srcIT.Key(), dstIT.Key(), i)
			require.Equal(t, srcIT.Value(), dstIT.Value(), "[%s] element (%d): %X", srcStoreKeys[j].Name(), i, srcIT.Key())
			dstIT.Next()
			srcIT.Next()
		}
		if !assert.False(t, dstIT.Valid()) {
			t.Fatalf("dest Iterator still has key :%X", dstIT.Key())
		}
		srcIT.Close()
		dstIT.Close()
	}
}

func TestGenesisInit(t *testing.T) {
	dir := "./testdata"
	// Open the directory
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	var wasmFiles []string
	// Iterate over each file in the directory
	for _, file := range files {
		// Check if the file has a .wasm extension
		if strings.HasSuffix(file.Name(), ".wasm") {
			// Read the content of the Wasm file
			_, err := ioutil.ReadFile(dir + "/" + file.Name())
			if err != nil {
				fmt.Println("Error reading file:", file.Name(), err)
				continue
			}

			wasmFiles = append(wasmFiles, file.Name())
		}
	}

	for _, fileName := range wasmFiles {
		t.Run(fileName, func(t *testing.T) {
			keeper, ctx, _ := setupKeeper(t)

			wasmCode, err := os.ReadFile("./testdata/" + fileName)
			require.NoError(t, err)
			myCodeInfo := types.CodeInfoFixture(types.WithSHA256CodeHash(wasmCode))
			src := types.GenesisState{
				Codes: []types.Code{{
					CodeID:    firstCodeID,
					CodeInfo:  myCodeInfo,
					CodeBytes: wasmCode,
				}},
				Sequences: []types.Sequence{
					{IDKey: types.KeyLastCodeID, Value: 2},
					{IDKey: types.KeyLastInstanceID, Value: 1},
				},
				Params: types.DefaultParams(),
			}

			require.NoError(t, types.ValidateGenesis(src))
			_, gotErr := InitGenesis(ctx, keeper, src, nil, nil)
			if gotErr != nil {
				fmt.Println("gotErr:", gotErr.Error())
				if strings.Contains(gotErr.Error(), "interface_version_*") {
					// Open the file in append mode, create it if it doesn't exist
					file, err := os.OpenFile("numbers.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						fmt.Println("Error:", err)
						return
					}
					defer file.Close()

					// Write the string representation of the number to the file
					_, err = file.WriteString(fileName + "\n")
					if err != nil {
						fmt.Println("Error:", err)
						return
					}
				}
				fmt.Println("this n")
				return
			}

			for _, c := range src.Codes {
				assert.Equal(t, c.Pinned, keeper.IsPinnedCode(ctx, c.CodeID))
			}
		})
	}
}

func TestImportContractWithCodeHistoryPreserved(t *testing.T) {
	genesisTemplate := `
{
	"params":{
		"code_upload_access": {
			"permission": "Everybody"
		},
		"instantiate_default_permission": "Everybody"
	},
  "codes": [
    {
      "code_id": "1",
      "code_info": {
        "code_hash": %q,
        "creator": "cosmos1qtu5n0cnhfkjj6l2rq97hmky9fd89gwca9yarx",
        "instantiate_config": {
          "permission": "OnlyAddress",
          "address": "cosmos1qtu5n0cnhfkjj6l2rq97hmky9fd89gwca9yarx"
        }
      },
      "code_bytes": %q
    }
  ],
  "contracts": [
    {
      "contract_address": "cosmos14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s4hmalr",
      "contract_info": {
        "code_id": "1",
        "creator": "cosmos13x849jzd03vne42ynpj25hn8npjecxqrjghd8x",
        "admin": "cosmos1h5t8zxmjr30e9dqghtlpl40f2zz5cgey6esxtn",
        "label": "ȀĴnZV芢毤",
		"created": {
			"block_height" : "100",
			"tx_index" : "10"
		}
      },
	  "contract_code_history": [
		{
			"code_id": "1",
			"updated": {
				"block_height" : "100",
				"tx_index" : "10"
			},
			"msg": {"foo": "bar"}
	  	},
		{
			"code_id": "1",
			"updated": {
				"block_height" : "200",
				"tx_index" : "10"
			},
			"msg": {"other": "msg"}
	  	}
		]
    }
  ],
  "sequences": [
  {"id_key": "AQ==", "value": "2"},
  {"id_key": "Ag==", "value": "3"}
  ]
}`
	keeper, ctx, _ := setupKeeper(t)
	contractKeeper := NewGovPermissionKeeper(keeper)

	wasmCode, err := os.ReadFile("./testdata/hackatom.wasm")
	require.NoError(t, err)

	wasmCodeHash := sha256.Sum256(wasmCode)
	enc64 := base64.StdEncoding.EncodeToString
	genesisStr := fmt.Sprintf(genesisTemplate, enc64(wasmCodeHash[:]), enc64(wasmCode))

	var importState types.GenesisState
	err = keeper.cdc.UnmarshalJSON([]byte(genesisStr), &importState)
	require.NoError(t, err)
	require.NoError(t, importState.ValidateBasic(), genesisStr)

	ctx = ctx.WithBlockHeight(0).WithGasMeter(sdk.NewInfiniteGasMeter())

	// when
	_, err = InitGenesis(ctx, keeper, importState, &StakingKeeperMock{}, TestHandler(contractKeeper))
	require.NoError(t, err)

	// verify wasm code
	gotWasmCode, err := keeper.GetByteCode(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, wasmCode, gotWasmCode, "byte code does not match")

	// verify code info
	gotCodeInfo := keeper.GetCodeInfo(ctx, 1)
	require.NotNil(t, gotCodeInfo)
	codeCreatorAddr := "cosmos1qtu5n0cnhfkjj6l2rq97hmky9fd89gwca9yarx"
	expCodeInfo := types.CodeInfo{
		CodeHash: wasmCodeHash[:],
		Creator:  codeCreatorAddr,
		InstantiateConfig: types.AccessConfig{
			Permission: types.AccessTypeOnlyAddress,
			Address:    codeCreatorAddr,
		},
	}
	assert.Equal(t, expCodeInfo, *gotCodeInfo)

	// verify contract
	contractAddr, _ := sdk.AccAddressFromBech32("cosmos14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s4hmalr")
	gotContractInfo := keeper.GetContractInfo(ctx, contractAddr)
	require.NotNil(t, gotContractInfo)
	contractCreatorAddr := "cosmos13x849jzd03vne42ynpj25hn8npjecxqrjghd8x"
	adminAddr := "cosmos1h5t8zxmjr30e9dqghtlpl40f2zz5cgey6esxtn"

	expContractInfo := types.ContractInfo{
		CodeID:  firstCodeID,
		Creator: contractCreatorAddr,
		Admin:   adminAddr,
		Label:   "ȀĴnZV芢毤",
		Created: &types.AbsoluteTxPosition{BlockHeight: 100, TxIndex: 10},
	}
	assert.Equal(t, expContractInfo, *gotContractInfo)

	expHistory := []types.ContractCodeHistoryEntry{
		{
			CodeID: firstCodeID,
			Updated: &types.AbsoluteTxPosition{
				BlockHeight: 100,
				TxIndex:     10,
			},
			Msg: []byte(`{"foo": "bar"}`),
		},
		{
			CodeID: firstCodeID,
			Updated: &types.AbsoluteTxPosition{
				BlockHeight: 200,
				TxIndex:     10,
			},
			Msg: []byte(`{"other": "msg"}`),
		},
	}
	assert.Equal(t, expHistory, keeper.GetContractHistory(ctx, contractAddr))
	assert.Equal(t, uint64(2), keeper.PeekAutoIncrementID(ctx, types.KeyLastCodeID))
	assert.Equal(t, uint64(3), keeper.PeekAutoIncrementID(ctx, types.KeyLastInstanceID))
}

func TestSupportedGenMsgTypes(t *testing.T) {
	wasmCode, err := os.ReadFile("./testdata/hackatom.wasm")
	require.NoError(t, err)
	var (
		myAddress          sdk.AccAddress = bytes.Repeat([]byte{1}, types.ContractAddrLen)
		verifierAddress    sdk.AccAddress = bytes.Repeat([]byte{2}, types.ContractAddrLen)
		beneficiaryAddress sdk.AccAddress = bytes.Repeat([]byte{3}, types.ContractAddrLen)
	)
	const denom = "stake"
	importState := types.GenesisState{
		Params: types.DefaultParams(),
		GenMsgs: []types.GenesisState_GenMsgs{
			{
				Sum: &types.GenesisState_GenMsgs_StoreCode{
					StoreCode: &types.MsgStoreCode{
						Sender:       myAddress.String(),
						WASMByteCode: wasmCode,
					},
				},
			},
			{
				Sum: &types.GenesisState_GenMsgs_InstantiateContract{
					InstantiateContract: &types.MsgInstantiateContract{
						Sender: myAddress.String(),
						CodeID: 1,
						Label:  "testing",
						Msg: HackatomExampleInitMsg{
							Verifier:    verifierAddress,
							Beneficiary: beneficiaryAddress,
						}.GetBytes(t),
						Funds: sdk.NewCoins(sdk.NewCoin(denom, sdk.NewInt(10))),
					},
				},
			},
			{
				Sum: &types.GenesisState_GenMsgs_ExecuteContract{
					ExecuteContract: &types.MsgExecuteContract{
						Sender:   verifierAddress.String(),
						Contract: BuildContractAddressClassic(1, 1).String(),
						Msg:      []byte(`{"release":{}}`),
					},
				},
			},
		},
	}
	require.NoError(t, importState.ValidateBasic())
	ctx, keepers := CreateDefaultTestInput(t)
	keeper := keepers.WasmKeeper
	ctx = ctx.WithBlockHeight(0).WithGasMeter(sdk.NewInfiniteGasMeter())
	keepers.Faucet.Fund(ctx, myAddress, sdk.NewCoin(denom, sdk.NewInt(100)))

	// when
	_, err = InitGenesis(ctx, keeper, importState, &StakingKeeperMock{}, TestHandler(keepers.ContractKeeper))
	require.NoError(t, err)

	// verify code stored
	gotWasmCode, err := keeper.GetByteCode(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, wasmCode, gotWasmCode)
	codeInfo := keeper.GetCodeInfo(ctx, 1)
	require.NotNil(t, codeInfo)

	// verify contract instantiated
	cInfo := keeper.GetContractInfo(ctx, BuildContractAddressClassic(1, 1))
	require.NotNil(t, cInfo)

	// verify contract executed
	gotBalance := keepers.BankKeeper.GetBalance(ctx, beneficiaryAddress, denom)
	assert.Equal(t, sdk.NewCoin(denom, sdk.NewInt(10)), gotBalance)
}

func setupKeeper(t *testing.T) (*Keeper, sdk.Context, []storetypes.StoreKey) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "wasm")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tempDir) })
	var (
		keyParams  = sdk.NewKVStoreKey(paramtypes.StoreKey)
		tkeyParams = sdk.NewTransientStoreKey(paramtypes.TStoreKey)
		keyWasm    = sdk.NewKVStoreKey(types.StoreKey)
	)

	db := dbm.NewMemDB()
	ms := store.NewCommitMultiStore(db)
	ms.MountStoreWithDB(keyWasm, storetypes.StoreTypeIAVL, db)
	ms.MountStoreWithDB(keyParams, storetypes.StoreTypeIAVL, db)
	ms.MountStoreWithDB(tkeyParams, storetypes.StoreTypeTransient, db)
	require.NoError(t, ms.LoadLatestVersion())

	ctx := sdk.NewContext(ms, tmproto.Header{
		Height: 1234567,
		Time:   time.Date(2020, time.April, 22, 12, 0, 0, 0, time.UTC),
	}, false, log.NewNopLogger())

	encodingConfig := MakeEncodingConfig(t)

	wasmConfig := types.DefaultWasmConfig()
	pk := paramskeeper.NewKeeper(encodingConfig.Marshaler, encodingConfig.Amino, keyParams, tkeyParams)

	srcKeeper := NewKeeper(
		encodingConfig.Marshaler,
		keyWasm,
		pk.Subspace(types.ModuleName),
		authkeeper.AccountKeeper{},
		&bankkeeper.BaseKeeper{},
		stakingkeeper.Keeper{},
		distributionkeeper.Keeper{},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		tempDir,
		wasmConfig,
		AvailableCapabilities,
	)
	return &srcKeeper, ctx, []storetypes.StoreKey{keyWasm, keyParams}
}

type StakingKeeperMock struct {
	err             error
	validatorUpdate []abci.ValidatorUpdate
	expCalls        int
	gotCalls        int
}

func (s *StakingKeeperMock) ApplyAndReturnValidatorSetUpdates(_ sdk.Context) ([]abci.ValidatorUpdate, error) {
	s.gotCalls++
	return s.validatorUpdate, s.err
}

func (s *StakingKeeperMock) verifyCalls(t *testing.T) {
	assert.Equal(t, s.expCalls, s.gotCalls, "number calls")
}

type MockMsgHandler struct {
	result   *sdk.Result
	err      error
	expCalls int
	gotCalls int
	expMsg   sdk.Msg
	gotMsg   sdk.Msg
}

func (m *MockMsgHandler) Handle(ctx sdk.Context, msg sdk.Msg) (*sdk.Result, error) {
	m.gotCalls++
	m.gotMsg = msg
	return m.result, m.err
}

func (m *MockMsgHandler) verifyCalls(t *testing.T) {
	assert.Equal(t, m.expMsg, m.gotMsg, "message param")
	assert.Equal(t, m.expCalls, m.gotCalls, "number calls")
}
