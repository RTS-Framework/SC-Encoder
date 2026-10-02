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

  // decrypt the loop time and prevent continuous 0x00
  mov {{.Reg.edx}}, {{hex .NumLoopStub}}       {{iji}}
  xor {{.Reg.edx}}, {{hex .NumLoopMaskA}}      {{iji}}
  xor {{.Reg.edx}}, {{hex .NumLoopMaskB}}      {{iji}}

  // check the loop time is zero
  test {{.Reg.edx}}, {{.Reg.edx}}              {{iji}}
  jz exit_loop                                 {{iji}}

  // calculate the body address
  lea {{.Reg.rbp}}, [rip + body + {{hex .OffsetT}}]   {{iji}}
  add {{.Reg.rbp}}, {{hex .OffsetA}}                  {{iji}}
  sub {{.Reg.rbp}}, {{hex .OffsetS}}                  {{iji}}

  // unshuffle shellcode body
 loop_unshuffle:
  // seed = seed * multiplier + increment
  imul {{.Reg.rax}}, {{.Reg.rbx}}              {{iji}}
  add {{.Reg.rax}}, {{.Reg.rcx}}               {{iji}}

  // save seed and calculate seed >> 3
  push {{.Reg.rax}}                            {{iji}}
  shr {{.Reg.rax}}, 3                          {{iji}}

  // reserve space for store the div result
  sub rsp, 8                                   {{iji}}

  // save context
  push rax                                     {{iji}}
  push rcx                                     {{iji}}
  push rdx                                     {{iji}}

  // seed % (i + 1)
  mov rax, {{.Reg.rax}}                        {{iji}}
  mov rcx, {{.Reg.rdx}}                        {{iji}}
  inc rcx                                      {{iji}}
  xor rdx, rdx                                 {{iji}}
  div rcx                                      {{iji}}

  // store the div result
  mov [rsp+24], rdx                            {{iji}}

  // restore context
  pop rdx                                      {{iji}}
  pop rcx                                      {{iji}}
  pop rax                                      {{iji}}

  // dump the div result for swap data
  mov {{.Reg.rdi}}, [rsp]                      {{iji}}

  // restore stack
  add rsp, 8                                   {{iji}}

  // restore seed
  pop {{.Reg.rax}}                             {{iji}}


  mov r15, {{.Reg.rax}}

  // swap data[i] and data[j]
  // mov {{.Reg.al}}, [{{.Reg.rbp}} + {{.Reg.rsi}} ]
  // xchg {{.Reg.al}},  [{{.Reg.rbp}} + {{.Reg.rdx}}]
  // mov [{{.Reg.rbp}} + {{.Reg.rsi}}], {{.Reg.al}}


  // update loop counter
  dec {{.Reg.edx}}                             {{iji}}
  jnz loop_unshuffle                           {{iji}}
 exit_loop:

  // restore context
  popfq                                        {{iji}}
  pop {{.Reg.rdi}}                             {{iji}}
  pop {{.Reg.rsi}}                             {{iji}}
  pop {{.Reg.rbp}}                             {{iji}}
  pop {{.Reg.rdx}}                             {{iji}}
  pop {{.Reg.rcx}}                             {{iji}}
  pop {{.Reg.rbx}}                             {{iji}}
  pop {{.Reg.rax}}                             {{iji}}


  mov rax, r15

body:
  ret
  // loader or raw shellcode
