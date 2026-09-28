package encoder

import (
	"bytes"
	"embed"
	"fmt"
	"text/template"
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

// The role of the shellcode loader is used to execute the shellcode
// without destroying the CPU context, erase the loader before execution
// and erase the shellcode after execution.
var (
	//go:embed loader/loader_x86.asm
	defaultLoaderX86 string

	//go:embed loader/loader_x64.asm
	defaultLoaderX64 string
)

type loaderCtx struct {
	SaveContext    []byte
	RestoreContext []byte

	StubKey any

	DecoderStub   []byte
	EraserStub    []byte
	CryptoKeyStub []byte

	CryptoKeyLen int
	ShellcodeLen int
	EraserLen    int

	EraseShellcode bool
}

func (enc *Encoder) addLoader(shellcode []byte) ([]byte, error) {
	if enc.opts.MinifyMode {
		return shellcode, nil
	}
	var loader string
	switch enc.arch {
	case 32:
		loader = enc.getLoaderX86()
	case 64:
		loader = enc.getLoaderX64()
	}
	asm, sc, err := enc.buildLoader(loader, shellcode)
	if err != nil {
		return nil, err
	}
	inst, err := enc.assemble(asm)
	if err != nil {
		return nil, err
	}
	return append(inst, sc...), nil
}

func (enc *Encoder) getLoaderX86() string {
	if enc.opts.LoaderX86 != "" {
		return enc.opts.LoaderX86
	}
	return defaultLoaderX86
}

func (enc *Encoder) getLoaderX64() string {
	if enc.opts.LoaderX64 != "" {
		return enc.opts.LoaderX64
	}
	return defaultLoaderX64
}

func (enc *Encoder) buildLoader(loader string, shellcode []byte) (string, []byte, error) {
	// append instructions for "IV" about encoder
	shellcode = append(enc.buildJunkInst(false), shellcode...)
	// append instructions to tail for prevent brute-force
	tail := enc.randBytes(64 + len(shellcode)/40)
	shellcode = append(shellcode, tail...)
	// generate crypto key for shellcode decoder
	cryptoKey := enc.randBytes(32)
	var (
		stubKey   any
		eraserLen int
	)
	switch enc.arch {
	case 32:
		stubKey = enc.rand.Uint32()
		eraserLen = len(eraserX86) + enc.rand.Intn(len(cryptoKey))
		shellcode = encrypt32(shellcode, cryptoKey)
	case 64:
		stubKey = enc.rand.Uint64()
		eraserLen = len(eraserX64) + enc.rand.Intn(len(cryptoKey))
		shellcode = encrypt64(shellcode, cryptoKey)
	}
	enc.key = cryptoKey
	enc.stubKey = stubKey
	// parse loader template
	tpl, err := template.New("loader").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"iji": enc.insertJunkInst,
	}).Parse(loader)
	if err != nil {
		return "", nil, fmt.Errorf("invalid assembly source template: %s", err)
	}
	ctx := loaderCtx{
		StubKey:        stubKey,
		DecoderStub:    enc.decoderStub(),
		EraserStub:     enc.eraserStub(),
		CryptoKeyStub:  enc.cryptoKeyStub(),
		CryptoKeyLen:   len(cryptoKey),
		ShellcodeLen:   len(shellcode),
		EraserLen:      eraserLen,
		EraseShellcode: enc.opts.EraseInst,
	}
	if enc.opts.SaveContext {
		ctx.SaveContext = enc.saveContext()
		ctx.RestoreContext = enc.restoreContext()
	}
	// build source from template and assemble it
	buf := bytes.NewBuffer(make([]byte, 0, 4096))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build assembly source: %s", err)
	}
	return buf.String(), shellcode, nil
}
