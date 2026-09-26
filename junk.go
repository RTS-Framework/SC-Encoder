package encoder

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"text/template"
)

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

	// for random immediate data with [0, 32) and [0, 64)
	Less32 map[string]int
	Less64 map[string]int
}

// the output garbage instruction length is no limit.
func (enc *Encoder) garbageInst() []byte {
	if enc.opts.NoGarbage {
		return nil
	}
	// random not insert garbage
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
	switch enc.rand.Intn(2 + numJunkCodes) {
	case 0:
		return enc.garbageJumpShort(2, 16)
	case 1:
		return enc.garbageMultiByteNOP()
	default:
		return enc.garbageTemplate()
	}
}

// the output garbage instruction length is <= 7 bytes.
func (enc *Encoder) garbageInstShort() []byte {
	if enc.opts.NoGarbage {
		return nil
	}
	switch enc.rand.Intn(2) {
	case 0:
		return enc.garbageJumpShort(2, 5)
	case 1:
		return enc.garbageMultiByteNOP()
	default:
		panic("invalid garbage instruction selection")
	}
}

// 0xEB, rel, [min, max] random bytes.
func (enc *Encoder) garbageJumpShort(min, max int) []byte {
	if min < 1 || max > 127 {
		panic("garbage jump short length out of range")
	}
	jmp := make([]byte, 0, 1+max/2)
	offset := min + enc.rand.Intn(max-min+1)
	jmp = append(jmp, 0xEB, byte(offset)) // #nosec G115
	jmp = append(jmp, enc.randBytes(offset)...)
	return jmp
}

func (enc *Encoder) garbageMultiByteNOP() []byte {
	var nop []byte
	switch enc.rand.Intn(2) {
	case 0:
		nop = []byte{0x90}
	case 1:
		nop = []byte{0x66, 0x90}
	}
	return nop
}

func (enc *Encoder) garbageTemplate() []byte {
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
	asm, err := enc.buildJunkCode(src)
	if err != nil {
		panic(err)
	}
	// assemble junk code
	inst, err := enc.assemble(asm)
	if err != nil {
		panic(fmt.Sprintf("failed to assemble junk code: %s", err))
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
	// process assembly source
	tpl, err := template.New("junk_code").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
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
	Less32 := make(map[string]int)
	Less64 := make(map[string]int)
	for i := 'A'; i <= 'Z'; i++ {
		b := enc.rand.Intn(2) == 0
		switches[string(i)] = b
		switches[string(i+0x20)] = b
		BYTE[string(i)] = int8(enc.rand.Int31() % 128)
		WORD[string(i)] = int16(enc.rand.Int31() % 32768)
		DWORD[string(i)] = enc.rand.Int31()
		QWORD[string(i)] = enc.rand.Int63()
		Less32[string(i)] = enc.rand.Intn(32)
		Less64[string(i)] = enc.rand.Intn(64)
	}
	ctx := junkCodeCtx{
		Reg:    enc.buildRandomRegisterMap(),
		Switch: switches,
		BYTE:   BYTE,
		WORD:   WORD,
		DWORD:  DWORD,
		QWORD:  QWORD,
		Less32: Less32,
		Less64: Less64,
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return "", fmt.Errorf("failed to build junk code assembly source: %s", err)
	}
	return buf.String(), nil
}
