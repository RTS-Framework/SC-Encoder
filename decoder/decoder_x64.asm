.code64

// iji means insert junk instruction
// ijs means insert junk instruction with short version

// rax store the seed
// rbx store the key and multiplier
// rcx store the increment
// rdx store the loop times
// rbp store the body address
// rsi store the swapped data
// rdi store the swapped offset

entry:
  // save context
  push {{.Reg.rax}}                            {{iji}}
  push {{.Reg.rbx}}                            {{iji}}
  push {{.Reg.rcx}}                            {{iji}}
  push {{.Reg.rdx}}                            {{iji}}
  push {{.Reg.rbp}}                            {{iji}}
  push {{.Reg.rsi}}                            {{iji}}
  push {{.Reg.rdi}}                            {{iji}}
  pushfq                                       {{iji}}

  // load seed and key
  mov {{.Reg.rax}}, {{hex .Seed}}              {{iji}}
  mov {{.Reg.rbx}}, {{hex .Key}}               {{iji}}

  // decrypt increment
  mov {{.Reg.rcx}}, {{hex .Imm.Inc}}           {{iji}}
  xor {{.Reg.rcx}}, {{.Reg.rbx}}               {{iji}}

  // decrypt multiplier and destroy key
  mov {{.Reg.rdx}}, {{hex .Imm.Mul}}           {{iji}}
  xor {{.Reg.rbx}}, {{.Reg.rdx}}               {{iji}}

  // prevent continuous 0x00
  mov {{.Reg.edx}}, {{hex .NumLoopStub}}       {{iji}}
  xor {{.Reg.edx}}, {{hex .NumLoopMaskA}}      {{iji}}
  xor {{.Reg.edx}}, {{hex .NumLoopMaskB}}      {{iji}}

  // calculate the body address
  lea {{.Reg.rbp}}, [rip + body + {{hex .OffsetT}}]   {{iji}}
  add {{.Reg.rbp}}, {{hex .OffsetA}}                  {{iji}}
  sub {{.Reg.rbp}}, {{hex .OffsetS}}                  {{iji}}

  // unshuffle shellcode body
 loop_unshuffle:
  // seed = seed * multiplier + increment
  imul {{.Reg.rax}}, {{.Reg.rbx}}              {{iji}}
  add {{.Reg.rax}}, {{.Reg.rcx}}               {{iji}}

  // calculate swapped
  shr {{.Reg.rax}}, 3

  // sub rsp, 8

  push rax
  push rcx
  push rdx

  // seed % (i + 1)
  mov rax, {{.Reg.rax}}
  mov rcx, {{.Reg.rdx}}
  inc rcx
  xor rdx, rdx
  div rcx

  // mov [rsp+24], rdx

  pop rdx
  pop rcx
  pop rax

  // mov {{.Reg.rdx}}, [rsp]
  // add rsp, 8

  // swap data[i] and data[j]
  // mov {{.Reg.al}}, [{{.Reg.rbp}} + {{.Reg.rsi}} ]
  // xchg {{.Reg.al}},  [{{.Reg.rbp}} + {{.Reg.rdx}}]
  // mov [{{.Reg.rbp}} + {{.Reg.rsi}}], {{.Reg.al}}


  // update counter
  dec {{.Reg.edx}}                             {{iji}}
  jnz loop_unshuffle                           {{iji}}

  // restore context
  popfq                                        {{iji}}
  pop {{.Reg.rdi}}                             {{iji}}
  pop {{.Reg.rsi}}                             {{iji}}
  pop {{.Reg.rbp}}                             {{iji}}
  pop {{.Reg.rdx}}                             {{iji}}
  pop {{.Reg.rcx}}                             {{iji}}
  pop {{.Reg.rbx}}                             {{iji}}
  pop {{.Reg.rax}}                             {{iji}}

body:
  ret
  // loader or raw shellcode
