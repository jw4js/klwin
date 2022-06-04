.intel_syntax noprefix

.global win_call_stub

save_regs:
push rax
push rbx
push rcx
push rdx
push rdi
push rsi
push rbp
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
jmp [rsp + 120]

restore_regs:
add rsp,8
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rbp
pop rsi
pop rdi
pop rdx
pop rcx
pop rbx
pop rax
add rsp,8
jmp [rsp - 136]

win_call_stub:
call save_regs
mov rdi,rsp
call win_call_stub_c
call restore_regs
ret

.global call_driver_entry
call_driver_entry:
call save_regs
mov rcx,rsi
xor rax,rax
xor rbx,rbx
xor rdi,rdi
xor rsi,rsi
xor rbp,rbp
xor r8,r8
xor r9,r9
xor r10,r10
xor r11,r11
xor r12,r12
xor r13,r13
xor r14,r14
xor r15,r15
call [rsp + 80]
push rax
call restore_regs
pop rax
ret
