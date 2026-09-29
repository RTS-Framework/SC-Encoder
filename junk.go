package encoder

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"text/template"
)

const maxJunkInstShortSize = 7

// The role of the junk code is to make the instruction sequence
// as featureless as possible.
var (
	//go:embed junk/*_x86.asm
	defaultJunkCodeFSx86 embed.FS

	//go:embed junk/*_x64.asm
	defaultJunkCodeFSx64 embed.FS

	defaultJunkCodeX86 = readJunkCodeTemplates(defaultJunkCodeFSx86)
	defaultJunkCodeX64 = readJunkCodeTemplates(defaultJunkCodeFSx64)
)

func readJunkCodeTemplates(efs embed.FS) []string {
	var templates []string
	err := fs.WalkDir(efs, ".", func(name string, entry fs.DirEntry, _ error) error {
		if entry.IsDir() {
			return nil
		}
		file, err := efs.Open(name)
		if err != nil {
			panic(err)
		}
		data, err := io.ReadAll(file)
		if err != nil {
			panic(err)
		}
		templates = append(templates, string(data))
		return nil
	})
	if err != nil {
		panic(err)
	}
	return templates
}

type junkCodeCtx struct {
	// for replace registers
	Reg map[string]string

	// for insert random instruction pair
	Switch map[string]bool

	// for random immediate data
	BYTE  map[string]int8
	WORD  map[string]int16
	DWORD map[string]int32
	QWORD map[string]int64

	// for random immediate data
	Less16 map[string]int // [1, 15]
	Less32 map[string]int // [1, 31]
	Less64 map[string]int // [1, 63]
}

func (enc *Encoder) insertJunkInst() string {
	if enc.opts.NoJunkCode {
		return ""
	}
	return ";" + toDB(enc.genJunkInst())
}

func (enc *Encoder) insertJunkInstShort() string {
	if enc.opts.NoJunkCode {
		return ""
	}
	return ";" + toDB(enc.genJunkInstShort())
}

func (enc *Encoder) genJunkInst() []byte {
	if enc.opts.NoJunkCode {
		return nil
	}
	return enc.buildJunkInst(false)
}

// the output junk instruction length is <= 7 bytes.
func (enc *Encoder) genJunkInstShort() []byte {
	if enc.opts.NoJunkCode {
		return nil
	}
	return enc.buildJunkInst(true)
}

func (enc *Encoder) buildJunkInst(short bool) []byte {
	if enc.opts.NoJunkCode {
		return nil
	}
	// random not insert junk instruction
	if enc.rand.Intn(10) == 0 {
		return nil
	}
	var numJunkCodes int
	switch enc.arch {
	case 32:
		numJunkCodes = len(enc.getJunkCodeX86())
	case 64:
		numJunkCodes = len(enc.getJunkCodeX64())
	}
	// dynamically adjust probability
	switch enc.rand.Intn(3 + numJunkCodes) {
	case 0:
		return nil
	case 1:
		return enc.junkMultiByteNOP()
	case 2:
		if short {
			return enc.junkJumpShort(2, 5)
		}
		return enc.junkJumpShort(2, 16)
	default:
		return enc.junkTemplate(short)
	}
}

func (enc *Encoder) junkMultiByteNOP() []byte {
	var nop []byte
	switch enc.rand.Intn(2) {
	case 0:
		nop = []byte{0x90}
	case 1:
		nop = []byte{0x66, 0x90}
	}
	return nop
}

// 0xEB, rel, [min, max] random bytes.
func (enc *Encoder) junkJumpShort(min, max int) []byte {
	if min < 1 || max > 127 {
		panic("junk jump short length out of range")
	}
	jmp := make([]byte, 0, 1+max/2)
	offset := min + enc.rand.Intn(max-min+1)
	jmp = append(jmp, 0xEB, byte(offset)) // #nosec G115
	jmp = append(jmp, enc.randBytes(offset)...)
	return jmp
}

func (enc *Encoder) junkTemplate(short bool) []byte {
	var junkCodes []string
	switch enc.arch {
	case 32:
		junkCodes = enc.getJunkCodeX86()
	case 64:
		junkCodes = enc.getJunkCodeX64()
	}
	// select random junk code template
	idx := enc.rand.Intn(len(junkCodes))
	src := junkCodes[idx]
	// if source contains the mark about insertJunkInst,
	// not assemble it and return for build faster.
	if short && strings.Contains(src, "{{iji}}") {
		return enc.junkMultiByteNOP()
	}
	// assemble junk code
	asm, err := enc.buildJunkCode(src)
	if err != nil {
		panic(err)
	}
	if len(asm) == 0 {
		panic("empty output junk code source")
	}
	inst, err := enc.assemble(asm)
	if err != nil {
		panic(fmt.Sprintf("failed to assemble junk code: %s", err))
	}
	if len(inst) == 0 {
		panic("assemble junk code source with unknown error")
	}
	if short && len(inst) > maxJunkInstShortSize {
		return enc.junkMultiByteNOP()
	}
	return inst
}

func (enc *Encoder) getJunkCodeX86() []string {
	if len(enc.opts.JunkCodeX86) > 0 {
		return enc.opts.JunkCodeX86
	}
	return defaultJunkCodeX86
}

func (enc *Encoder) getJunkCodeX64() []string {
	if len(enc.opts.JunkCodeX64) > 0 {
		return enc.opts.JunkCodeX64
	}
	return defaultJunkCodeX64
}

// #nosec G115
func (enc *Encoder) buildJunkCode(src string) (string, error) {
	// process template
	tpl, err := template.New("junk_code").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"iji": enc.insertJunkInst,
	}).Parse(src)
	if err != nil {
		return "", fmt.Errorf("invalid junk code template: %s", err)
	}
	// initialize random data
	switches := make(map[string]bool)
	BYTE := make(map[string]int8)
	WORD := make(map[string]int16)
	DWORD := make(map[string]int32)
	QWORD := make(map[string]int64)
	Less16 := make(map[string]int)
	Less32 := make(map[string]int)
	Less64 := make(map[string]int)
	for i := 'A'; i <= 'Z'; i++ {
		b := enc.rand.Intn(2) == 0
		i8 := int8(enc.rand.Int31() % 128)
		i16 := int16(enc.rand.Int31() % 32768)
		i32 := enc.rand.Int31()
		i64 := enc.rand.Int63()
		l16 := 1 + enc.rand.Intn(15)
		l32 := 1 + enc.rand.Intn(31)
		l64 := 1 + enc.rand.Intn(63)
		switches[string(i+0x00)] = b
		switches[string(i+0x20)] = b
		BYTE[string(i+0x00)] = i8
		BYTE[string(i+0x20)] = i8
		WORD[string(i+0x00)] = i16
		WORD[string(i+0x20)] = i16
		DWORD[string(i+0x00)] = i32
		DWORD[string(i+0x20)] = i32
		QWORD[string(i+0x00)] = i64
		QWORD[string(i+0x20)] = i64
		Less16[string(i+0x00)] = l16
		Less16[string(i+0x20)] = l16
		Less32[string(i+0x00)] = l32
		Less32[string(i+0x20)] = l32
		Less64[string(i+0x00)] = l64
		Less64[string(i+0x20)] = l64
	}
	ctx := junkCodeCtx{
		Reg:    enc.buildRandomRegisterMap(),
		Switch: switches,
		BYTE:   BYTE,
		WORD:   WORD,
		DWORD:  DWORD,
		QWORD:  QWORD,
		Less16: Less16,
		Less32: Less32,
		Less64: Less64,
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return "", fmt.Errorf("failed to build junk code source: %s", err)
	}
	return buf.String(), nil
}
