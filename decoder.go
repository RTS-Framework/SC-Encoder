package encoder

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"
	"math"
	"text/template"
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

// The role of the decoder is to eliminate the instruction
// sequence features as much as possible.
var (
	//go:embed decoder/decoder_x86.asm
	defaultDecoderX86 string

	//go:embed decoder/decoder_x64.asm
	defaultDecoderX64 string
)

type decoderCtx struct {
	// for replace registers
	Reg  map[string]string
	RegV map[string]string
	RegN map[string]string

	// xor with key
	Imm map[string]any

	// unshuffle seed and xor key
	Seed any
	Key  any

	// for prevent continuous 0x00
	NumLoopStub  int32
	NumLoopMaskA int32
	NumLoopMaskB int32

	// T + A = S
	OffsetT int32
	OffsetA int32
	OffsetS int32

	// for prevent call short
	Padding bool
	PadData []byte
}

func (enc *Encoder) addDecoder(input []byte) ([]byte, error) {
	var decoder string
	switch enc.arch {
	case 32:
		decoder = enc.getDecoderX86()
	case 64:
		decoder = enc.getDecoderX64()
	}
	asm, body, err := enc.buildDecoder(decoder, input)
	if err != nil {
		return nil, err
	}
	inst, err := enc.assemble(asm)
	if err != nil {
		return nil, err
	}
	return append(inst, body...), nil
}

func (enc *Encoder) buildDecoder(decoder string, input []byte) (string, []byte, error) {
	// parse decoder template
	tpl, err := template.New("decoder").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"iji": enc.insertJunkInst,
		"ijs": enc.insertJunkInstShort,
	}).Parse(decoder)
	if err != nil {
		return "", nil, fmt.Errorf("invalid decoder template: %s", err)
	}
	// generate seed for shuffle body data
	// generate key for xor immediate value map.
	var (
		seed any
		key  any
	)
	switch enc.arch {
	case 32:
		seed = enc.rand.Uint32()
		key = enc.rand.Uint32()
	case 64:
		seed = enc.rand.Uint64()
		key = enc.rand.Uint64()
	}
	// shuffle input and store transformed seed
	body, seed := enc.shuffle(input, seed)
	// generate loop value
	numLoopMaskA := enc.rand.Int31()
	numLoopMaskB := enc.rand.Int31()
	numLoopStub := int32(len(input)) ^ numLoopMaskA ^ numLoopMaskB // #nosec G115
	// generate offset for calculate rip
	offsetT := enc.rand.Int31n(math.MaxInt32 >> 12)
	offsetA := enc.rand.Int31n(math.MaxInt32 >> 10)
	offsetS := offsetT + offsetA
	ctx := decoderCtx{
		Reg:  enc.buildRandomRegisterMap(),
		RegV: enc.buildVolatileRegisterMap(),
		RegN: enc.buildNonvolatileRegisterMap(),

		Imm: enc.buildImmediateValueMap(key),

		Seed: seed,
		Key:  key,

		NumLoopStub:  numLoopStub,
		NumLoopMaskA: numLoopMaskA,
		NumLoopMaskB: numLoopMaskB,

		OffsetT: offsetT,
		OffsetA: offsetA,
		OffsetS: offsetS,
	}
	// add padding data at tail of decoder
	if !enc.opts.MinifyMode {
		ctx.Padding = true
		ctx.PadData = enc.randBytes(8 + enc.rand.Intn(48))
	}
	// build source from template and assemble it
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build decoder source: %s", err)
	}
	return buf.String(), body, nil
}

func (enc *Encoder) getDecoderX86() string {
	if enc.opts.DecoderX86 != "" {
		return enc.opts.DecoderX86
	}
	return defaultDecoderX86
}

func (enc *Encoder) getDecoderX64() string {
	if enc.opts.DecoderX64 != "" {
		return enc.opts.DecoderX64
	}
	return defaultDecoderX64
}

func (enc *Encoder) shuffle(data []byte, seed any) ([]byte, any) {
	data = bytes.Clone(data)
	var advanced any
	switch enc.arch {
	case 32:
		seed := seed.(uint32)
		for i := len(data) - 1; i > 0; i-- {
			j := seed % uint32(i+1)
			t := data[i]
			data[i] = data[j]
			data[j] = t
			seed = lcg32(seed)
		}
		advanced = seed
	case 64:
		seed := seed.(uint64)
		for i := len(data) - 1; i > 0; i-- {
			j := seed % uint64(i+1)
			t := data[i]
			data[i] = data[j]
			data[j] = t
			seed = lcg64(seed)
		}
		advanced = seed
	}
	return data, advanced
}

func (enc *Encoder) buildImmediateValueMap(key any) map[string]any {
	imm := make(map[string]any)
	switch enc.arch {
	case 32:
		for _, item := range []struct {
			key string
			val uint32
		}{
			{"v_5", 5},
			{"v_13", 13},
			{"v_17", 17},
		} {
			imm[item.key] = item.val ^ key.(uint32)
		}
	case 64:
		for _, item := range []struct {
			key string
			val uint64
		}{
			{"v_5", 5},
			{"v_13", 13},
			{"v_17", 17},
		} {
			imm[item.key] = item.val ^ key.(uint64)
		}
	}
	return imm
}

func (enc *Encoder) decoderStub() []byte {
	var decoder []byte
	switch enc.arch {
	case 32:
		decoder = decoderX86
	case 64:
		decoder = decoderX64
	}
	return enc.miniXOR(decoder, enc.stubKey)
}

func (enc *Encoder) eraserStub() []byte {
	var eraser []byte
	switch enc.arch {
	case 32:
		// eraser = eraserX86
	case 64:
		// eraser = eraserX64
	}
	return enc.miniXOR(eraser, enc.stubKey)
}

func (enc *Encoder) cryptoKeyStub() []byte {
	return enc.miniXOR(enc.key, enc.stubKey)
}

func (enc *Encoder) miniXOR(inst []byte, key any) []byte {
	var output []byte
	switch enc.arch {
	case 32:
		output = enc.miniXOR32(inst, key.(uint32))
	case 64:
		output = enc.miniXOR64(inst, key.(uint64))
	}
	return output
}

func (enc *Encoder) miniXOR32(inst []byte, key uint32) []byte {
	// ensure the instructions length can be divisible by 4.
	inst = bytes.Clone(inst)
	numPad := len(inst) % 4
	if numPad != 0 {
		numPad = 4 - numPad
	}
	inst = append(inst, enc.randBytes(numPad)...)
	for i := 0; i < len(inst); i += 4 {
		val := binary.LittleEndian.Uint32(inst[i:])
		binary.LittleEndian.PutUint32(inst[i:], val^key)
	}
	return inst
}

func (enc *Encoder) miniXOR64(inst []byte, key uint64) []byte {
	// ensure the instructions length can be divisible by 8.
	inst = bytes.Clone(inst)
	numPad := len(inst) % 8
	if numPad != 0 {
		numPad = 8 - numPad
	}
	inst = append(inst, enc.randBytes(numPad)...)
	for i := 0; i < len(inst); i += 8 {
		val := binary.LittleEndian.Uint64(inst[i:])
		binary.LittleEndian.PutUint64(inst[i:], val^key)
	}
	return inst
}

func (enc *Encoder) xsrl(inst []byte, seed, key uint32) []byte {
	// ensure the instructions length can be divisible by 4.
	inst = bytes.Clone(inst)
	numPad := len(inst) % 4
	if numPad != 0 {
		numPad = 4 - numPad
	}
	inst = append(inst, enc.randBytes(numPad)...)
	for i := 0; i < len(inst); i += 4 {
		val := binary.LittleEndian.Uint32(inst[i:])
		switch enc.arch {
		case 32:
			val ^= key
			val = ror32(val, 17)
			val ^= seed
			val = rol32(val, 5)
		case 64:
			val ^= key
			val = ror32(val, 7)
			val ^= seed
			val = rol32(val, 17)
		}
		binary.LittleEndian.PutUint32(inst[i:], val)
		seed = xorShift32(seed)
	}
	return inst
}

// #nosec G115
func encrypt32(data, key []byte) []byte {
	output := make([]byte, len(data))
	last := binary.LittleEndian.Uint32(key[:4])
	ctr := binary.LittleEndian.Uint32(key[4:])
	keyIdx := int(last % uint32(len(key)))
	for i := 0; i < len(data); i++ {
		b := data[i]
		b ^= byte(last)
		b = rol(b, uint8(last%8))
		b ^= key[keyIdx]
		b += byte(ctr ^ last)
		b = ror(b, uint8(last%8))
		output[i] = b
		// update key index
		keyIdx++
		if keyIdx >= len(key) {
			keyIdx = 0
		}
		ctr++
		last = xorShift32(last)
	}
	return output
}

// #nosec G115
func encrypt64(data, key []byte) []byte {
	output := make([]byte, len(data))
	last := binary.LittleEndian.Uint64(key[:8])
	ctr := binary.LittleEndian.Uint64(key[8:])
	keyIdx := int(last % uint64(len(key)))
	for i := 0; i < len(data); i++ {
		b := data[i]
		b ^= byte(last)
		b = rol(b, uint8(last%8))
		b ^= key[keyIdx]
		b += byte(ctr ^ last)
		b = ror(b, uint8(last%8))
		output[i] = b
		// update key index
		keyIdx++
		if keyIdx >= len(key) {
			keyIdx = 0
		}
		ctr++
		last = xorShift64(last)
	}
	return output
}

func lcg32(seed uint32) uint32 {
	return seed*0x19660D + 0x3C6EF35F
}

func lcg64(seed uint64) uint64 {
	return seed*0x5851F42D4C957F2D + 0x14057B7EF767814F
}

func reverseLCG32(seed uint32) uint32 {
	return seed*0xFEE058C5 + 0x25D60FE5
}

func reverseLCG64(seed uint64) uint64 {
	return seed*0xC097EF87329E28A5 + 0x9995B5B621535015
}

func xorShift32(seed uint32) uint32 {
	seed ^= seed << 13
	seed ^= seed >> 17
	seed ^= seed << 5
	return seed
}

func xorShift64(seed uint64) uint64 {
	seed ^= seed << 13
	seed ^= seed >> 7
	seed ^= seed << 17
	return seed
}

func ror(value byte, bits uint8) byte {
	return value>>bits | value<<(8-bits)
}

func rol(value byte, bits uint8) byte {
	return value<<bits | value>>(8-bits)
}

func ror32(value uint32, bits uint8) uint32 {
	return value>>bits | value<<(32-bits)
}

func rol32(value uint32, bits uint8) uint32 {
	return value<<bits | value>>(32-bits)
}
