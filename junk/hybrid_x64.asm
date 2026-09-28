.code64

entry:
  pushfq
  push {{.Reg.rax}}

{{if .Switch.A}}
  mov {{.Reg.rax}}, {{.Reg.rbx}}
  test {{.Reg.rax}}, {{.Reg.rax}}
  jnz next_1
  xor {{.Reg.rax}}, {{.Reg.rsi}}
  {{iji}}
 next_1:
  call func_1
{{end}}

{{if .Switch.B}}
  xor {{.Reg.rax}}, {{.Reg.rcx}}
  {{iji}}
  jmp leave
{{end}}

  xor {{.Reg.rax}}, {{.Reg.rdi}}

{{if .Switch.C}}
  xor {{.Reg.rax}}, {{.DWORD.D}}
  call func_2
{{end}}

{{if .Switch.D}}
  mov {{.Reg.rax}}, {{.WORD.E}}
  test {{.Reg.rax}}, {{.Reg.rax}}
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
  ror {{.Reg.rax}}, {{.Less32.A}}
  xor {{.Reg.rax}}, {{.Reg.rdi}}
  rol {{.Reg.rax}}, {{.Less32.B}}
  call func_3
{{end}}

 leave:
  pop {{.Reg.rax}}
  popfq
  jmp exit

func_1:
  {{iji}}
  ret

func_2:
  push {{.Reg.rbx}}
  mov {{.Reg.rbx}}, {{.Reg.rcx}}
{{if .Switch.G}}
  test {{.Reg.rbx}}, {{.Reg.rbx}}
  jnz next_2
  call func_3
  {{iji}}
 next_2:
  call func_1
{{end}}
  pop {{.Reg.rbx}}
  ret

func_3:
  rol {{.Reg.rax}}, {{.Less32.C}}
{{if .Switch.H}}
  {{iji}}
{{end}}
  ret

exit:
