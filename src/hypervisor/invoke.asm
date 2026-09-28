.code
	launch_raw_hypercall proc frame
		push rbx
		.pushreg rbx
		.endprolog
		cpuid
		pop rbx
		ret
	launch_raw_hypercall endp

    launch_diagnostic_hypercall proc frame
        push rbx
        .pushreg rbx
        push r12
        .pushreg r12
        .endprolog
        mov r12, [rsp+56] ; fifth argument, before CPUID clobbers volatile registers
        xor eax, eax     ; unknown capability on an older backend returns zero
        cpuid
        mov [r12], rax
        mov [r12+8], rdx
        mov [r12+16], r8
        mov [r12+24], r9
        mov [r12+32], rbx
        mov [r12+40], rcx
        pop r12
        pop rbx
        ret
    launch_diagnostic_hypercall endp
    launch_walk_hypercall proc frame
        push rbx
        .pushreg rbx
        push r12
        .pushreg r12
        push rbp
        .pushreg rbp
        push rsi
        .pushreg rsi
        .endprolog
        mov r12, [rsp+72] ; fifth argument: original rsp+40, plus four pushes
        xor eax, eax
        xor r10d, r10d   ; old backends leave these registers untouched
        xor r11d, r11d
        xor ebp, ebp
        xor esi, esi
        cpuid
        mov [r12], rax
        mov [r12+8], rdx
        mov [r12+16], r8
        mov [r12+24], r9
        mov [r12+32], rbx
        mov [r12+40], rcx
        mov [r12+48], r10
        mov [r12+56], r11
        mov [r12+64], rbp
        mov [r12+72], rsi
        pop rsi
        pop rbp
        pop r12
        pop rbx
        ret
    launch_walk_hypercall endp
END
