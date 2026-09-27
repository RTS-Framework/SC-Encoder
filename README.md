# SC-Encoder
A simple shellcode encoder, it supports custom decoder and loader templates.

## Usage
```bash
sc-encoder -arch 64 -i shellcode.bin -o shellcode_x64.bin
```

## Development
```go
package main

import (
    "encoding/hex"
    "fmt"
    "os"

    "github.com/RTS-Framework/SC-Encoder"
)

func main() {
    enc := encoder.NewEncoder()
    
    shellcode, err := os.ReadFile("shellcode.bin")
    checkError(err)

    opts := encoder.Options{
        NumIterator: 4,
        NumTailInst: 64,
        MinifyMode:  false,
        SaveContext: false,
        EraseInst:   false,
        NoIterator:  false,
        NoJunkCode:  false,
    }
    ctx, err := enc.Encode(shellcode, 64, &opts)
    checkError(err)

    out := hex.EncodeToString(ctx.Output)
    fmt.Println(out)

    err = enc.Close()
    checkError(err)
}

func checkError(err error) {
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
```

## Disclaimer
This project is developed solely for security research, educational purposes, and authorized penetration testing.
Any use for illegal activities, unauthorized access to computer systems, or malicious purposes is strictly prohibited.

By using this project, you agree that:

1. You will only use it in environments you own or have explicit authorization to test.
2. You are solely responsible for ensuring compliance with all applicable local, state, national, and international laws and regulations.
3. The authors and contributors assume no liability and are not responsible for any misuse or damage caused by this project.
4. You understand that unauthorized use of computer systems is a criminal offense in most jurisdictions

This software is provided "as is" without warranty of any kind, express or implied. Use at your own risk.
