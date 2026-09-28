.code32

entry:
  pushfd
  push {{.Reg.eax}}

{{if .Switch.A}}
  mov {{.Reg.eax}}, {{.Reg.ebx}}
  test {{.Reg.eax}}, {{.Reg.eax}}
  jnz next_1
  xor {{.Reg.eax}}, {{.Reg.esi}}
  {{iji}}
 next_1:
  call func_1
{{end}}

{{if .Switch.B}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  {{iji}}
  jmp leave
{{end}}

  xor {{.Reg.eax}}, {{.Reg.edi}}

{{if .Switch.C}}
  xor {{.Reg.eax}}, {{.DWORD.D}}
  call func_2
{{end}}

{{if .Switch.D}}
  mov {{.Reg.eax}}, {{.WORD.E}}
  test {{.Reg.eax}}, {{.Reg.eax}}
  jnz next_3
  call func_1
  {{iji}}
 next_3:
  {{if .Switch.E}}
    {{iji}}
  {{end}}
  jmp leave
{{end}}

  call func_2

{{if .Switch.F}}
  ror {{.Reg.eax}}, {{.Less32.A}}
  xor {{.Reg.eax}}, {{.Reg.edi}}
  rol {{.Reg.eax}}, {{.Less32.B}}
  call func_3
{{end}}

 leave:
  pop {{.Reg.eax}}
  popfd
  jmp exit

func_1:
  {{iji}}
  ret

func_2:
  push {{.Reg.ebx}}
  mov {{.Reg.ebx}}, {{.Reg.ecx}}
{{if .Switch.G}}
  test {{.Reg.ebx}}, {{.Reg.ebx}}
  jnz next_2
  call func_3
  {{iji}}
 next_2:
  call func_1
{{end}}
  pop {{.Reg.ebx}}
  ret

func_3:
  rol {{.Reg.eax}}, {{.Less32.C}}
{{if .Switch.H}}
  {{iji}}
{{end}}
  ret

exit:
