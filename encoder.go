package encoder

import (
	cr "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/For-ACGN/go-keystone"
)

// Encoder is a simple shellcode encoder.
type Encoder struct {
	rand *rand.Rand

	// assembler engine
	ase32 *keystone.Engine
	ase64 *keystone.Engine

	// context arguments
	arch int
	opts *Options
	key  []byte

	// stub key for xor stubs
	stubKey any

	// save and restore context
	contextSeq []int
}

// Options contains options about encode shellcode.
type Options struct {
	// the number of iterate.
	NumIterate int `toml:"num_iterate" json:"num_iterate"`

	// the size of the junk instruction at tail.
	NumTailInst int `toml:"num_tail_inst" json:"num_tail_inst"`

	// only use the mini loader, not use loader
	// for erase shellcode and more feature.
	MinifyMode bool `toml:"minify_mode" json:"minify_mode"`

	// save and restore context after call shellcode.
	SaveContext bool `toml:"save_context" json:"save_context"`

	// erase loader instruction and shellcode after call it.
	EraseInst bool `toml:"erase_inst" json:"erase_inst"`

	// disable iterator, not recommend.
	NoIterator bool `toml:"no_iterator" json:"no_iterator"`

	// disable junk instruction, not recommend.
	NoJunkCode bool `toml:"no_junk_code" json:"no_junk_code"`

	// specify a random seed for encoder.
	RandSeed int64 `toml:"rand_seed" json:"rand_seed"`

	// trim the seed at the tail of output.
	TrimSeed bool `toml:"trim_seed" json:"trim_seed"`

	// specify the x86 mini decoder template.
	MiniDecoderX86 string `toml:"mini_decoder_x86" json:"mini_decoder_x86"`

	// specify the x64 mini decoder template.
	MiniDecoderX64 string `toml:"mini_decoder_x64" json:"mini_decoder_x64"`

	// specify the x86 loader template.
	LoaderX86 string `toml:"loader_x86" json:"loader_x86"`

	// specify the x64 loader template.
	LoaderX64 string `toml:"loader_x64" json:"loader_x64"`

	// specify the x86 junk code templates.
	JunkCodeX86 []string `toml:"junk_code_x86" json:"junk_code_x86"`

	// specify the x64 junk code templates.
	JunkCodeX64 []string `toml:"junk_code_x64" json:"junk_code_x64"`
}

// Context contains the output and context data in Encode.
type Context struct {
	Output      []byte `json:"output"`
	Seed        int64  `json:"seed"`
	NumIterate  int    `json:"num_iterate"`
	MinifyMode  bool   `json:"minify_mode"`
	NoJunkCode  bool   `json:"no_junk_code"`
	SaveContext bool   `json:"save_context"`
	EraseInst   bool   `json:"erase_inst"`
}

// NewEncoder is used to create a simple shellcode encoder.
func NewEncoder() *Encoder {
	var seed int64
	buf := make([]byte, 8)
	_, err := cr.Read(buf)
	if err == nil {
		seed = int64(binary.LittleEndian.Uint64(buf)) // #nosec G115
	} else {
		seed = time.Now().UnixNano()
	}
	encoder := Encoder{
		rand: rand.New(rand.NewSource(seed)), // #nosec
	}
	return &encoder
}

// Encode is used to encode input shellcode to a unique shellcode.
func (enc *Encoder) Encode(shellcode []byte, arch int, opts *Options) (ctx *Context, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	if len(shellcode) == 0 {
		return nil, errors.New("empty shellcode")
	}
	switch arch {
	case 32, 64:
	default:
		return nil, fmt.Errorf("unsupported architecture: %d", arch)
	}
	if opts == nil {
		opts = new(Options)
	}
	enc.arch = arch
	enc.opts = opts
	// initialize keystone engine
	err = enc.initAssembler()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize assembler: %s", err)
	}
	// set random seed
	seed := opts.RandSeed
	if seed == 0 {
		seed = enc.rand.Int63()
	}
	enc.rand.Seed(seed)
	// encode the raw shellcode and add loader
	output, err := enc.addLoader(shellcode)
	if err != nil {
		return nil, err
	}
	// insert mini decoder at the prefix
	output, err = enc.addMiniDecoder(output)
	if err != nil {
		return nil, err
	}
	// iterate the encoding of the pre-decoder and part of the shellcode
	numIter := opts.NumIterate
	if numIter < 1 {
		numIter = 2 + enc.rand.Intn(4)
	}
	if opts.NoIterator {
		numIter = 0
	}
	for i := 0; i < numIter; i++ {
		output, err = enc.addMiniDecoder(output)
		if err != nil {
			return nil, err
		}
	}
	// padding junk code at the tail
	if !opts.NoJunkCode {
		times := 8 + enc.rand.Intn((numIter+1)*4)
		size := enc.rand.Intn(16 * times)
		output = append(output, enc.randBytes(size)...)
	}
	// append garbage data to tail for prevent brute-force
	output = append(output, enc.randBytes(opts.NumTailInst)...)
	// append garbage data to the output shellcode prefix
	output = append(enc.buildJunkInst(false), output...)
	// append the random seed to tail
	if !opts.TrimSeed {
		buf := binary.BigEndian.AppendUint64(nil, uint64(seed)) // #nosec G115
		output = append(output, buf...)
	}
	// build encode context for test and debug
	ctx = &Context{
		Output:      output,
		Seed:        seed,
		NumIterate:  numIter,
		MinifyMode:  opts.MinifyMode,
		NoJunkCode:  opts.NoJunkCode,
		SaveContext: opts.SaveContext,
		EraseInst:   opts.EraseInst,
	}
	return ctx, nil
}

func (enc *Encoder) initAssembler() error {
	var (
		ase *keystone.Engine
		err error
	)
	switch enc.arch {
	case 32:
		if enc.ase32 != nil {
			return nil
		}
		ase, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		if err != nil {
			return err
		}
		enc.ase32 = ase
	case 64:
		if enc.ase64 != nil {
			return nil
		}
		ase, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		if err != nil {
			return err
		}
		enc.ase64 = ase
	default:
		panic("unreachable code")
	}
	return ase.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
}

func (enc *Encoder) assemble(src string) ([]byte, error) {
	if strings.Contains(src, "<no value>") {
		return nil, errors.New("invalid register in assembly source")
	}
	if strings.Contains(src, "<nil>") {
		return nil, errors.New("invalid usage in assembly source")
	}
	switch enc.arch {
	case 32:
		return enc.ase32.Assemble(src, 0)
	case 64:
		return enc.ase64.Assemble(src, 0)
	default:
		panic("unreachable code")
	}
}

func (enc *Encoder) randBytes(n int) []byte {
	buf := make([]byte, n)
	_, _ = enc.rand.Read(buf)
	return buf
}

// Close is used to close shellcode encoder.
func (enc *Encoder) Close() error {
	if enc.ase32 != nil {
		err := enc.ase32.Close()
		if err != nil {
			return err
		}
		enc.ase32 = nil
	}
	if enc.ase64 != nil {
		err := enc.ase64.Close()
		if err != nil {
			return err
		}
		enc.ase64 = nil
	}
	return nil
}
