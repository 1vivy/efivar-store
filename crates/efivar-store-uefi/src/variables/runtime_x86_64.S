.text
.balign 16
.global efivar_store_blob_start
.global efivar_store_blob_end
.global efivar_store_index
.global efivar_store_get
.global efivar_store_next
.global efivar_store_set
.global efivar_store_query
efivar_store_blob_start:
# Only the index slot is relocated by installation; all code references are RIP relative.
efivar_store_get:
    test rcx, rcx
    jz .Linvalid
    test rdx, rdx
    jz .Linvalid
    test r9, r9
    jz .Linvalid
    xor r10d, r10d
    xor r11d, r11d
.Lvalidate_get_name:
    cmp r10d, 512
    jae .Linvalid
    movzx eax, word ptr [rcx+r10]
    test eax, eax
    jz .Lvalidate_get_end
    add r10d, 2
    test r11d, r11d
    jnz .Lvalidate_get_low
    cmp eax, 0xd800
    jb .Lvalidate_get_name
    cmp eax, 0xdbff
    jbe .Lvalidate_get_high
    cmp eax, 0xdfff
    jbe .Linvalid
    jmp .Lvalidate_get_name
.Lvalidate_get_high:
    mov r11d, 1
    jmp .Lvalidate_get_name
.Lvalidate_get_low:
    cmp eax, 0xdc00
    jb .Linvalid
    cmp eax, 0xdfff
    ja .Linvalid
    xor r11d, r11d
    jmp .Lvalidate_get_name
.Lvalidate_get_end:
    test r10d, r10d
    jz .Linvalid
    test r11d, r11d
    jnz .Linvalid
    push rsi
    push rdi
    push rbx
    push r12
    push r13
    mov r12, r9
    mov r13, r8
    mov rbx, [rsp + 80]
    mov rsi, [rip + efivar_store_index]
    test rsi, rsi
    jz .Lget_corrupt
    mov rax, 0x3158444956524653
    cmp [rsi], rax
    jne .Lget_corrupt
    cmp dword ptr [rsi+8], 72
    jb .Lget_corrupt
    cmp dword ptr [rsi+8], 2097152
    ja .Lget_corrupt
    mov r10d, [rsi+12]
    cmp r10d, 512
    ja .Lget_corrupt
    add rsi, 72
.Lget_loop:
    test r10d, r10d
    jz .Lget_missing
    mov rax, [rdx]
    cmp [rsi], rax
    jne .Lget_advance
    mov rax, [rdx+8]
    cmp [rsi+8], rax
    jne .Lget_advance
    xor r11d, r11d
.Lget_name:
    cmp r11d, [rsi+20]
    jae .Lget_advance
    mov ax, [rcx+r11]
    cmp ax, [rsi+r11+32]
    jne .Lget_advance
    add r11d, 2
    test ax, ax
    jne .Lget_name
    mov edi, [rsi+24]
    cmp [r12], rdi
    jb .Lget_small
    test rdi, rdi
    jz .Lget_copy
    test rbx, rbx
    jz .Lget_invalid
.Lget_copy:
    mov [r12], rdi
    test r13, r13
    jz .Lget_noattr
    mov eax, [rsi+16]
    mov [r13], eax
.Lget_noattr:
    mov ecx, [rsi+20]
    lea rsi, [rsi+rcx+32]
    mov rcx, rdi
    mov rdi, rbx
    rep movsb
    xor eax, eax
    jmp .Lget_done
.Lget_small:
    mov [r12], rdi
    mov eax, 5
    jmp .Lget_error
.Lget_advance:
    mov eax, [rsi+28]
    add rsi, rax
    dec r10d
    jmp .Lget_loop
.Lget_missing:
    mov eax, 14
    jmp .Lget_error
.Lget_invalid:
    mov eax, 2
    jmp .Lget_error
.Lget_corrupt:
    mov eax, 33
.Lget_error:
    bts rax, 63
.Lget_done:
    pop r13
    pop r12
    pop rbx
    pop rdi
    pop rsi
    ret

efivar_store_next:
    test rcx, rcx
    jz .Linvalid
    test rdx, rdx
    jz .Linvalid
    test r8, r8
    jz .Linvalid
    cmp qword ptr [rcx], 2
    jb .Linvalid
    push rsi
    push rdi
    push rbx
    push r12
    mov r12, rcx
    mov rbx, rdx
    mov rsi, [rip+efivar_store_index]
    test rsi, rsi
    jz .Lnext_corrupt
    mov rax, 0x3158444956524653
    cmp [rsi], rax
    jne .Lnext_corrupt
    cmp dword ptr [rsi+8], 72
    jb .Lnext_corrupt
    cmp dword ptr [rsi+8], 2097152
    ja .Lnext_corrupt
    mov r10d, [rsi+12]
    cmp r10d, 512
    ja .Lnext_corrupt
    add rsi, 72
    cmp word ptr [rbx], 0
    je .Lnext_found
.Lnext_loop:
    test r10d, r10d
    jz .Lnext_invalid
    mov rax, [r8]
    cmp [rsi], rax
    jne .Lnext_advance
    mov rax, [r8+8]
    cmp [rsi+8], rax
    jne .Lnext_advance
    xor r11d, r11d
.Lnext_name:
    cmp r11, [r12]
    jae .Lnext_invalid
    cmp r11d, [rsi+20]
    jae .Lnext_advance
    mov ax, [rbx+r11]
    cmp ax, [rsi+r11+32]
    jne .Lnext_advance
    add r11d, 2
    test ax, ax
    jne .Lnext_name
    mov eax, [rsi+28]
    add rsi, rax
    dec r10d
    jmp .Lnext_found
.Lnext_advance:
    mov eax, [rsi+28]
    add rsi, rax
    dec r10d

    jmp .Lnext_loop
.Lnext_found:
    test r10d, r10d
    jz .Lnext_missing
    mov ecx, [rsi+20]
    cmp [r12], rcx
    jb .Lnext_small
    mov [r12], rcx
    mov rax, [rsi]
    mov [r8], rax
    mov rax, [rsi+8]
    mov [r8+8], rax
    add rsi, 32
    mov rdi, rbx
    rep movsb
    xor eax, eax
    jmp .Lnext_done
.Lnext_small:
    mov [r12], rcx
    mov eax, 5
    jmp .Lnext_error
.Lnext_missing:
    mov eax, 14
    jmp .Lnext_error
.Lnext_invalid:
    mov eax, 2
    jmp .Lnext_error
.Lnext_corrupt:
    mov eax, 33
.Lnext_error:
    bts rax, 63
.Lnext_done:
    pop r12
    pop rbx
    pop rdi
    pop rsi
    ret

efivar_store_set:
    mov eax, 3
    bts rax, 63
    ret
efivar_store_query:
    test rdx, rdx
    jz .Linvalid
    test r8, r8
    jz .Linvalid
    test r9, r9
    jz .Linvalid
    test ecx, 0xfffffff8
    jnz .Lunsupported
    test ecx, 2
    jz .Linvalid
    mov r10, [rip+efivar_store_index]
    test r10, r10
    jz .Lcorrupt
    mov rax, 0x3158444956524653
    cmp [r10], rax
    jne .Lcorrupt
    cmp dword ptr [r10+8], 72
    jb .Lcorrupt
    cmp dword ptr [r10+8], 2097152
    ja .Lcorrupt
    cmp dword ptr [r10+12], 512
    ja .Lcorrupt
    add r10, 24
    test ecx, 1
    jnz .Lquery_copy
    add r10, 24
.Lquery_copy:
    mov rax, [r10]
    mov [rdx], rax
    mov rax, [r10+8]
    mov [r8], rax
    mov rax, [r10+16]
    mov [r9], rax
    xor eax, eax
    ret
.Lunsupported:
    mov eax, 3
    bts rax, 63
    ret
.Lcorrupt:
    mov eax, 33
    bts rax, 63
    ret
.Linvalid:
    mov eax, 2
    bts rax, 63
    ret
.balign 8
efivar_store_index:
    .quad 0
efivar_store_blob_end:
