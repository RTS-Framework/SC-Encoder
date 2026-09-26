package encoder

import (
	"maps"
	"slices"
)

var (
	registerX86 = []string{
		"eax", "ebx", "ecx", "edx",
		"ebp", "edi", "esi",
	}

	regVolatileX86 = []string{
		"eax", "ecx", "edx",
	}

	regNonvolatileX86 = []string{
		"ebx", "ebp", "edi", "esi",
	}

	registerX64 = []string{
		"rax", "rbx", "rcx", "rdx",
		"rbp", "rdi", "rsi",
		"r8", "r9", "r10", "r11",
		"r12", "r13", "r14", "r15",
	}

	regVolatileX64 = []string{
		"rax", "rcx", "rdx",
		"r8", "r9", "r10", "r11",
	}

	regNonvolatileX64 = []string{
		"rbx", "rbp", "rdi", "rsi",
		"r12", "r13", "r14", "r15",
	}
)

func (enc *Encoder) buildRandomRegisterMap() map[string]string {
	var registers []string
	switch enc.arch {
	case 32:
		registers = registerX86
	case 64:
		registers = registerX64
	}
	return enc.buildRegisterMap(registers)
}

func (enc *Encoder) buildVolatileRegisterMap() map[string]string {
	var registers []string
	switch enc.arch {
	case 32:
		registers = regVolatileX86
	case 64:
		registers = regVolatileX64
	}
	return enc.buildRegisterMap(registers)
}

func (enc *Encoder) buildNonvolatileRegisterMap() map[string]string {
	var registers []string
	switch enc.arch {
	case 32:
		registers = regNonvolatileX86
	case 64:
		registers = regNonvolatileX64
	}
	return enc.buildRegisterMap(registers)
}

func (enc *Encoder) buildRegisterMap(registers []string) map[string]string {
	reg := enc.shuffleRegisterMap(registers)
	dword := enc.buildDWORDBitRegisterMap(reg)
	word := enc.buildWORDRegisterMap(reg)
	b := enc.buildBYTERegisterMap(reg)
	maps.Copy(reg, dword)
	maps.Copy(reg, word)
	maps.Copy(reg, b)
	return reg
}

func (enc *Encoder) shuffleRegisterMap(registers []string) map[string]string {
	src := registers
	dst := slices.Clone(registers)
	for {
		enc.rand.Shuffle(len(dst), func(i, j int) {
			dst[i], dst[j] = dst[j], dst[i]
		})
		var same bool
		for i := 0; i < len(src); i++ {
			if src[i] == dst[i] {
				same = true
				break
			}
		}
		if !same {
			break
		}
	}
	reg := make(map[string]string, len(src))
	for i := 0; i < len(src); i++ {
		reg[src[i]] = dst[i]
	}
	return reg
}
