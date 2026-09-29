package encoder

import (
	"fmt"
)

// InspectDecoderTemplate is used to test decoder template.
func InspectDecoderTemplate(arch int, src string) (string, []byte, error) {
	switch arch {
	case 32, 64:
	default:
		return "", nil, fmt.Errorf("unsupported architecture: %d", arch)
	}
	encoder := NewEncoder()
	encoder.arch = arch
	encoder.opts = &Options{
		NoJunkCode: true,
	}
	err := encoder.initAssembler()
	if err != nil {
		return "", nil, err
	}
	asm, _, err := encoder.buildDecoder(src, nil)
	if err != nil {
		return "", nil, err
	}
	inst, err := encoder.assemble(asm)
	if err != nil {
		return "", nil, fmt.Errorf("failed to assemble decoder: %s", err)
	}
	err = encoder.Close()
	if err != nil {
		return "", nil, err
	}
	return asm, inst, nil
}

// InspectLoaderTemplate is used to test loader template.
func InspectLoaderTemplate(arch int, src string) (string, []byte, error) {
	switch arch {
	case 32, 64:
	default:
		return "", nil, fmt.Errorf("unsupported architecture: %d", arch)
	}
	encoder := NewEncoder()
	encoder.arch = arch
	encoder.opts = &Options{
		NoJunkCode: true,
	}
	err := encoder.initAssembler()
	if err != nil {
		return "", nil, err
	}
	asm, _, err := encoder.buildLoader(src, nil)
	if err != nil {
		return "", nil, err
	}
	inst, err := encoder.assemble(asm)
	if err != nil {
		return "", nil, fmt.Errorf("failed to assemble loader: %s", err)
	}
	err = encoder.Close()
	if err != nil {
		return "", nil, err
	}
	return asm, inst, nil
}

// InspectJunkCodeTemplate is used to test junk code template.
func InspectJunkCodeTemplate(arch int, src string) (string, []byte, error) {
	switch arch {
	case 32, 64:
	default:
		return "", nil, fmt.Errorf("unsupported architecture: %d", arch)
	}
	encoder := NewEncoder()
	encoder.arch = arch
	encoder.opts = new(Options)
	err := encoder.initAssembler()
	if err != nil {
		return "", nil, err
	}
	asm, err := encoder.buildJunkCode(src)
	if err != nil {
		return "", nil, err
	}
	inst, err := encoder.assemble(asm)
	if err != nil {
		return "", nil, fmt.Errorf("failed to assemble junk code: %s", err)
	}
	err = encoder.Close()
	if err != nil {
		return "", nil, err
	}
	return asm, inst, nil
}
