package encoder

import (
	"bytes"
	"runtime"
	"testing"
	"unsafe"

	"github.com/For-ACGN/go-keystone"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestJunkCode(t *testing.T) {
	encoder := NewEncoder()

	opts := &Options{
		EraseInst:  true,
		NoIterator: false,
		NoJunkCode: false,
	}

	t.Run("x86", func(t *testing.T) {
		asm := ".code32\n"
		asm += "mov eax, dword ptr [esp+4]\n"
		asm += "mov dword ptr [eax], 0x86\n"
		asm += "mov eax, 0x86\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		ctx, err := encoder.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		spew.Dump(ctx)

		num := bytes.Count(ctx.Output, []byte{0x00, 0x00, 0x00})
		require.Less(t, num, 2)
		num = bytes.Count(ctx.Output, []byte{0xFF, 0xFF, 0xFF})
		require.Less(t, num, 1)

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}
		addr := loadShellcode(t, ctx.Output)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x86, int(ret))
		require.Equal(t, 0x86, val)

		// check shellcode is erased
		sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(ctx.Output))
		require.False(t, bytes.Contains(sc, shellcode))

		spew.Dump(sc)
		num = bytes.Count(sc, []byte{0x00, 0x00, 0x00})
		require.Less(t, num, 2)
		num = bytes.Count(sc, []byte{0xFF, 0xFF, 0xFF})
		require.Less(t, num, 1)
	})

	t.Run("x64", func(t *testing.T) {
		asm := ".code64\n"
		asm += "mov qword ptr [rcx], 0x64\n"
		asm += "mov rax, 0x64\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		ctx, err := encoder.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		spew.Dump(ctx)

		testFindSignature(t, ctx.Output)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}
		addr := loadShellcode(t, ctx.Output)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x64, int(ret))
		require.Equal(t, 0x64, val)

		// check shellcode is erased
		sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(ctx.Output))
		require.False(t, bytes.Contains(sc, shellcode))
		testFindSignature(t, sc)
	})

	shellcode := bytes.Clone(testAddX86)

	t.Run("invalid template", func(t *testing.T) {
		opts.JunkCodeX86 = []string{"{{.Invalid}}"}

		ctx, err := encoder.Encode(shellcode, 32, opts)
		require.ErrorContains(t, err, "failed to build junk code source")
		require.Nil(t, ctx)
	})

	t.Run("empty output", func(t *testing.T) {
		opts.JunkCodeX86 = []string{""}

		ctx, err := encoder.Encode(shellcode, 32, opts)
		require.ErrorContains(t, err, "empty output junk code source")
		require.Nil(t, ctx)
	})

	t.Run("invalid source", func(t *testing.T) {
		opts.JunkCodeX86 = []string{"invalid"}

		ctx, err := encoder.Encode(shellcode, 32, opts)
		errStr := "failed to assemble junk code: failed to assemble: "
		errStr += "Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)"
		require.ErrorContains(t, err, errStr)
		require.Nil(t, ctx)
	})

	t.Run("unknown error", func(t *testing.T) {
		opts.JunkCodeX86 = []string{"// unknown op"}

		ctx, err := encoder.Encode(shellcode, 32, opts)
		require.ErrorContains(t, err, "assemble junk code source with unknown error")
		require.Nil(t, ctx)
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func TestJunkJumpShort(t *testing.T) {
	encoder := NewEncoder()
	encoder.opts = new(Options)

	t.Run("x86", func(t *testing.T) {
		encoder.arch = 32

		for i := 0; i < 1000; i++ {
			size := len(encoder.junkJumpShort(2, 5))
			require.True(t, size >= 2+2 && size <= 5+2)
		}
	})

	t.Run("x64", func(t *testing.T) {
		encoder.arch = 64

		for i := 0; i < 1000; i++ {
			size := len(encoder.junkJumpShort(2, 5))
			require.True(t, size >= 2+2 && size <= 5+2)
		}
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func TestJunkTemplate(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		testJunkTemplate(t, 10, false)
	})

	t.Run("short", func(t *testing.T) {
		testJunkTemplate(t, 10, true)
	})
}

func TestJunkTemplateFuzz(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		testJunkTemplate(t, 1000, false)
	})

	t.Run("short", func(t *testing.T) {
		testJunkTemplate(t, 1000, true)
	})
}

func testJunkTemplate(t *testing.T, times int, short bool) {
	t.Run("x86", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.arch = 32
		encoder.opts = new(Options)
		err := encoder.initAssembler()
		require.NoError(t, err)

		for i := 0; i < times; i++ {
			data := encoder.junkTemplate(short)
			require.NotEmpty(t, data)
		}

		err = encoder.Close()
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.arch = 64
		encoder.opts = new(Options)
		err := encoder.initAssembler()
		require.NoError(t, err)

		for i := 0; i < times; i++ {
			data := encoder.junkTemplate(short)
			require.NotEmpty(t, data)
		}

		err = encoder.Close()
		require.NoError(t, err)
	})
}
