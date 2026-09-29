package encoder

import (
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestInspectDecoderTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		asm, inst, err := InspectDecoderTemplate(32, defaultDecoderX86)
		require.NoError(t, err)
		fmt.Println(asm)
		spew.Dump(inst)
	})

	t.Run("x64", func(t *testing.T) {
		asm, inst, err := InspectDecoderTemplate(64, defaultDecoderX64)
		require.NoError(t, err)
		fmt.Println(asm)
		spew.Dump(inst)
	})

	t.Run("invalid arch", func(t *testing.T) {
		asm, inst, err := InspectDecoderTemplate(123, "")
		require.EqualError(t, err, "unsupported architecture: 123")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})

	t.Run("invalid template", func(t *testing.T) {
		asm, inst, err := InspectDecoderTemplate(32, "{{.Invalid}}")
		require.ErrorContains(t, err, "failed to build decoder source")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})

	t.Run("invalid source", func(t *testing.T) {
		asm, inst, err := InspectDecoderTemplate(32, "invalid")
		errStr := "failed to assemble decoder: failed to assemble: "
		errStr += "Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)"
		require.EqualError(t, err, errStr)
		require.Nil(t, inst)
		require.NotZero(t, asm)
	})

	t.Run("unknown error", func(t *testing.T) {
		asm, inst, err := InspectDecoderTemplate(32, "// unknown op")
		require.EqualError(t, err, "assemble decoder source with unknown error")
		require.Nil(t, inst)
		require.NotZero(t, asm)
	})
}

func TestInspectLoaderTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		asm, inst, err := InspectLoaderTemplate(32, defaultLoaderX86)
		require.NoError(t, err)
		fmt.Println(asm)
		spew.Dump(inst)
	})

	t.Run("x64", func(t *testing.T) {
		asm, inst, err := InspectLoaderTemplate(64, defaultLoaderX64)
		require.NoError(t, err)
		fmt.Println(asm)
		spew.Dump(inst)
	})

	t.Run("invalid arch", func(t *testing.T) {
		asm, inst, err := InspectLoaderTemplate(123, "")
		require.EqualError(t, err, "unsupported architecture: 123")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})

	t.Run("invalid template", func(t *testing.T) {
		asm, inst, err := InspectLoaderTemplate(32, "{{.Invalid}}")
		require.ErrorContains(t, err, "failed to build shield source")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})

	t.Run("invalid source", func(t *testing.T) {
		asm, inst, err := InspectLoaderTemplate(32, "invalid")
		errStr := "failed to assemble shield: failed to assemble: "
		errStr += "Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)"
		require.EqualError(t, err, errStr)
		require.Nil(t, inst)
		require.NotZero(t, asm)
	})

	t.Run("unknown error", func(t *testing.T) {
		asm, inst, err := InspectLoaderTemplate(32, "// unknown op")
		require.EqualError(t, err, "assemble shield source with unknown error")
		require.Nil(t, inst)
		require.NotZero(t, asm)
	})
}

func TestInspectJunkCodeTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		for _, src := range defaultJunkCodeX86 {
			asm, inst, err := InspectJunkCodeTemplate(32, src)
			require.NoError(t, err)
			fmt.Println(asm)
			spew.Dump(inst)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for _, src := range defaultJunkCodeX64 {
			asm, inst, err := InspectJunkCodeTemplate(64, src)
			require.NoError(t, err)
			fmt.Println(asm)
			spew.Dump(inst)
		}
	})

	t.Run("invalid arch", func(t *testing.T) {
		asm, inst, err := InspectJunkCodeTemplate(123, "")
		require.EqualError(t, err, "unsupported architecture: 123")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})

	t.Run("invalid template", func(t *testing.T) {
		asm, inst, err := InspectJunkCodeTemplate(32, "{{.Invalid}}")
		require.ErrorContains(t, err, "failed to build junk code source")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})

	t.Run("invalid source", func(t *testing.T) {
		asm, inst, err := InspectJunkCodeTemplate(32, "invalid")
		errStr := "failed to assemble junk code: failed to assemble: "
		errStr += "Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)"
		require.EqualError(t, err, errStr)
		require.Nil(t, inst)
		require.NotZero(t, asm)
	})

	t.Run("unknown error", func(t *testing.T) {
		asm, inst, err := InspectJunkCodeTemplate(32, "// unknown op")
		require.EqualError(t, err, "assemble junk code source with unknown error")
		require.Nil(t, inst)
		require.NotZero(t, asm)
	})
}
