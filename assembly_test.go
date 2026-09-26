package encoder

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testAddX86 = []byte{
		0x31, 0xC0, //               xor eax, eax
		0x03, 0x44, 0x24, 0x04, //   add eax, [esp+04]
		0x03, 0x44, 0x24, 0x08, //   add eax, [esp+08]
		0xC2, 0x08, 0x00, //         ret 8
	}

	testAddX64 = []byte{
		0x31, 0xC0, //               xor eax, eax
		0x48, 0x01, 0xC8, //         add rax, rcx
		0x48, 0x01, 0xD0, //         add rax, rdx
		0xC3, //                     ret
	}
)

func TestMapRegDWORD(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		for _, item := range []string{
			"eax",
			"ebx",
			"ecx",
			"edx",
			"edi",
			"esi",
			"ebp",
		} {
			output := mapRegDWORD(item)
			require.Equal(t, item, output)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for _, item := range []*struct {
			input  string
			output string
		}{
			{"rax", "eax"},
			{"rbx", "ebx"},
			{"rcx", "ecx"},
			{"rdx", "edx"},
			{"rdi", "edi"},
			{"rsi", "esi"},
			{"rbp", "ebp"},
			{"r8", "r8d"},
			{"r9", "r9d"},
			{"r10", "r10d"},
			{"r11", "r11d"},
			{"r12", "r12d"},
			{"r13", "r13d"},
			{"r14", "r14d"},
			{"r15", "r15d"},
		} {
			output := mapRegDWORD(item.input)
			require.Equal(t, item.output, output)
		}
	})
}

func TestMapRegWORD(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		for _, item := range []*struct {
			input  string
			output string
		}{
			{"eax", "ax"},
			{"ebx", "bx"},
			{"ecx", "cx"},
			{"edx", "dx"},
			{"edi", "di"},
			{"esi", "si"},
			{"ebp", "bp"},
		} {
			output := mapRegWORD(item.input)
			require.Equal(t, item.output, output)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for _, item := range []*struct {
			input  string
			output string
		}{
			{"rax", "ax"},
			{"rbx", "bx"},
			{"rcx", "cx"},
			{"rdx", "dx"},
			{"rdi", "di"},
			{"rsi", "si"},
			{"rbp", "bp"},
			{"r8", "r8w"},
			{"r9", "r9w"},
			{"r10", "r10w"},
			{"r11", "r11w"},
			{"r12", "r12w"},
			{"r13", "r13w"},
			{"r14", "r14w"},
			{"r15", "r15w"},
		} {
			output := mapRegWORD(item.input)
			require.Equal(t, item.output, output)
		}
	})

	t.Run("invalid register", func(t *testing.T) {
		require.Panics(t, func() {
			mapRegWORD("xmm0")
		})
	})
}

func TestMapRegBYTE(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		for _, item := range []string{
			"eax",
			"ebx",
			"ecx",
			"edx",
			"edi",
			"esi",
			"ebp",
		} {
			output := mapRegBYTE(item)
			require.Equal(t, item, output)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for _, item := range []*struct {
			input  string
			output string
		}{
			{"rax", "al"},
			{"rbx", "bl"},
			{"rcx", "cl"},
			{"rdx", "dl"},
			{"rdi", "dil"},
			{"rsi", "sil"},
			{"rbp", "bpl"},
			{"r8", "r8b"},
			{"r9", "r9b"},
			{"r10", "r10b"},
			{"r11", "r11b"},
			{"r12", "r12b"},
			{"r13", "r13b"},
			{"r14", "r14b"},
			{"r15", "r15b"},
		} {
			output := mapRegBYTE(item.input)
			require.Equal(t, item.output, output)
		}
	})

	t.Run("invalid register", func(t *testing.T) {
		require.Panics(t, func() {
			mapRegBYTE("xmm0")
		})
	})
}

func TestPrintInstructions(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		binHex, insts, err := printInstructions(testAddX86, 32)
		require.NoError(t, err)
		t.Log(binHex)
		t.Log(insts)
	})

	t.Run("x64", func(t *testing.T) {
		binHex, insts, err := printInstructions(testAddX64, 64)
		require.NoError(t, err)
		t.Log(binHex)
		t.Log(insts)
	})
}

func TestToDB(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		data := []byte{1, 2, 3, 4}
		output := toDB(data)

		expected := ".byte 0x01, 0x02, 0x03, 0x04, "
		require.Equal(t, expected, output)
	})

	t.Run("empty bytes", func(t *testing.T) {
		output := toDB(nil)
		require.Empty(t, output)
	})
}

func TestToHex(t *testing.T) {
	output := toHex(15)
	require.Equal(t, "0xF", output)
}
