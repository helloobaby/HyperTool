extern SystemCallHandler:proc
extern OriKiSystemServiceStart:proc

.code

SAVE macro
	push rax
	push rcx
	push rdx
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	push rdi
	push rsi 
	push rbx
	push rbp
endm

RESTOR macro
	pop rbp
	pop rbx
	pop rsi
	pop rdi
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdx
	pop rcx
	pop rax
endm	

DetourKiSystemServiceStart proc
	
	;int 3
	pop r15
	SAVE
	sub rsp,28h
	mov rcx,rsp
	add rcx,160;A0h
	mov edx,eax
	call SystemCallHandler
	add rsp,28h
	RESTOR

	mov [rbx+90h],rsp
	mov     edi, eax
	shr     edi, 7
	and     edi, 20h
	and     eax, 0FFFh
	jmp qword ptr[OriKiSystemServiceStart]

DetourKiSystemServiceStart endp


end