package encoder

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"

	"github.com/For-ACGN/go-keystone"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestDecoder(t *testing.T) {
	encoder := NewEncoder()

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
		spew.Dump(shellcode)

		opts := &Options{
			MinifyMode: true,
			NoIterator: true,
			NoJunkCode: true,
		}
		ctx, err := encoder.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		spew.Dump(ctx)

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}
		addr := loadShellcode(t, ctx.Output)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x86, int(ret))
		require.Equal(t, 0x86, val)
		spew.Dump(unsafe.Slice((*byte)(unsafe.Pointer(addr)), ctx.Size))
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
		spew.Dump(shellcode)

		opts := &Options{
			MinifyMode: true,
			NoIterator: true,
			NoJunkCode: true,
		}
		ctx, err := encoder.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		spew.Dump(ctx)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}
		addr := loadShellcode(t, ctx.Output)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x64, int(ret))
		require.Equal(t, 0x64, val)
		spew.Dump(unsafe.Slice((*byte)(unsafe.Pointer(addr)), ctx.Size))
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func TestDecoderFuzz(t *testing.T) {
	encoder := NewEncoder()

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

		opts := &Options{
			MinifyMode: true,
			NoIterator: true,
			NoJunkCode: true,
		}

		for i := 0; i < 100; i++ {
			ctx, err := encoder.Encode(shellcode, 32, opts)
			require.NoError(t, err)
			fmt.Println("seed:", ctx.Seed)

			if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
				continue
			}
			addr := loadShellcode(t, ctx.Output)
			var val int
			ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
			require.Equal(t, 0x86, int(ret))
			require.Equal(t, 0x86, val)
		}
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

		opts := &Options{
			MinifyMode: true,
			NoIterator: true,
			NoJunkCode: true,
		}

		for i := 0; i < 100; i++ {
			ctx, err := encoder.Encode(shellcode, 64, opts)
			require.NoError(t, err)
			fmt.Println("seed:", ctx.Seed)

			if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
				continue
			}
			addr := loadShellcode(t, ctx.Output)
			var val int
			ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
			require.Equal(t, 0x64, int(ret))
			require.Equal(t, 0x64, val)
		}
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func TestLCG(t *testing.T) {
	t.Run("32", func(t *testing.T) {
		seed := uint32(123456789)
		next := lcg32(seed)
		prev := reverseLCG32(next)
		require.Equal(t, seed, prev)
	})

	t.Run("64", func(t *testing.T) {
		seed := uint64(12345678912345)
		next := lcg64(seed)
		prev := reverseLCG64(next)
		require.Equal(t, seed, prev)
	})
}
