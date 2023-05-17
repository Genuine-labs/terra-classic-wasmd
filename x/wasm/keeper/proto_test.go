package keeper

import (
	"encoding/hex"
	"testing"

	"github.com/CosmWasm/wasmd/x/wasm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestProto(t *testing.T) {
	codec := MakeTestCodec(t)

	address, err := sdk.AccAddressFromHex("012345")
	require.NoError(t, err)

	codeHash := []byte{0x01}

	codeInfo := types.CodeInfo{
		CodeHash:          codeHash,
		Creator:           address.String(),
		InstantiateConfig: types.AccessConfig{},
	}

	codeInfoNew := types.CodeInfoNew{
		CodeHash:          codeHash,
		Creator:           address.String(),
		InstantiateConfig: types.AccessConfig{},
	}

	bz := codec.MustMarshal(&codeInfo)
	bzNew := codec.MustMarshal(&codeInfoNew)

	println(hex.EncodeToString(bz))
	println(hex.EncodeToString(bzNew))

	codeInfoNewDes := types.CodeInfoNew{}
	codec.MustUnmarshal(bz, &codeInfoNewDes)

	// serialized bz not equal
	require.NotEqual(t, bz, bzNew)

	// CodeHash & Creator will swith values
	require.Equal(t, codeInfo.CodeHash, []byte(codeInfoNewDes.Creator))
	require.Equal(t, codeInfo.Creator, string(codeInfoNewDes.CodeHash))
}
