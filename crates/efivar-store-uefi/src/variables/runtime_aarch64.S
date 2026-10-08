.text
.balign 16
.global efivar_store_blob_start
.global efivar_store_blob_end
.global efivar_store_index
.global efivar_store_get
.global efivar_store_next
.global efivar_store_set
.global efivar_store_query
.macro validate_index base, temp, tempw, count
    ldr \temp, [\base]
    ldr x17, .Lindex_magic
    cmp \temp, x17
    b.ne .Lcorrupt
    ldr \tempw, [\base, #8]
    cmp \tempw, #72
    b.lo .Lcorrupt
    mov x17, #2097152
    cmp \temp, x17
    b.hi .Lcorrupt
    ldr \count, [\base, #12]
    cmp \count, #512
    b.hi .Lcorrupt
.endm
efivar_store_blob_start:
efivar_store_get:
    cbz x0, .Linvalid
    cbz x1, .Linvalid
    cbz x3, .Linvalid
    mov x5, #0
    mov w6, #0
.Lvalidate_get_name:
    cmp x5, #512
    b.hs .Linvalid
    ldrh w7, [x0, x5]
    cbz w7, .Lvalidate_get_end
    add x5, x5, #2
    cbnz w6, .Lvalidate_get_low
    mov w8, #0xd800
    cmp w7, w8
    b.lo .Lvalidate_get_name
    mov w8, #0xdbff
    cmp w7, w8
    b.ls .Lvalidate_get_high
    mov w8, #0xdfff
    cmp w7, w8
    b.ls .Linvalid
    b .Lvalidate_get_name
.Lvalidate_get_high:
    mov w6, #1
    b .Lvalidate_get_name
.Lvalidate_get_low:
    mov w8, #0xdc00
    cmp w7, w8
    b.lo .Linvalid
    mov w8, #0xdfff
    cmp w7, w8
    b.hi .Linvalid
    mov w6, #0
    b .Lvalidate_get_name
.Lvalidate_get_end:
    cbz x5, .Linvalid
    cbnz w6, .Linvalid
    adr x5, efivar_store_index
    ldr x5, [x5]
    cbz x5, .Lcorrupt
    validate_index x5, x7, w7, w6
    add x5, x5, #72
.Lget_loop:
    cbz w6, .Lmissing
    ldp x7, x8, [x1]
    ldp x9, x10, [x5]
    cmp x7, x9
    b.ne .Lget_advance
    cmp x8, x10
    b.ne .Lget_advance
    mov x7, #0
    ldr w8, [x5, #20]
    add x9, x5, #32
.Lget_name:
    cmp x7, x8
    b.hs .Lget_advance
    ldrh w10, [x0, x7]
    ldrh w11, [x9, x7]
    cmp w10, w11
    b.ne .Lget_advance
    add x7, x7, #2
    cbnz w10, .Lget_name
    ldr w10, [x5, #24]
    ldr x11, [x3]
    cmp x11, x10
    b.lo .Lget_small
    cbz x10, .Lget_copy
    cbz x4, .Linvalid
.Lget_copy:
    str x10, [x3]
    cbz x2, .Lget_noattr
    ldr w11, [x5, #16]
    str w11, [x2]
.Lget_noattr:
    add x9, x9, x8
    mov x7, #0
.Lget_bytes:
    cmp x7, x10
    b.hs .Lsuccess
    ldrb w11, [x9, x7]
    strb w11, [x4, x7]
    add x7, x7, #1
    b .Lget_bytes
.Lget_small:
    str x10, [x3]
    b .Lsmall
.Lget_advance:
    ldr w7, [x5, #28]
    add x5, x5, x7
    sub w6, w6, #1
    b .Lget_loop

efivar_store_next:
    cbz x0, .Linvalid
    cbz x1, .Linvalid
    cbz x2, .Linvalid
    ldr x3, [x0]
    cmp x3, #2
    b.lo .Linvalid
    adr x5, efivar_store_index
    ldr x5, [x5]
    cbz x5, .Lcorrupt
    validate_index x5, x7, w7, w6
    add x5, x5, #72
    ldrh w7, [x1]
    cbz w7, .Lnext_found
.Lnext_loop:
    cbz w6, .Linvalid
    ldp x7, x8, [x2]
    ldp x9, x10, [x5]
    cmp x7, x9
    b.ne .Lnext_advance
    cmp x8, x10
    b.ne .Lnext_advance
    mov x7, #0
    ldr w8, [x5, #20]
    add x9, x5, #32
.Lnext_name:
    cmp x7, x3
    b.hs .Linvalid
    cmp x7, x8
    b.hs .Lnext_advance
    ldrh w10, [x1, x7]
    ldrh w11, [x9, x7]
    cmp w10, w11
    b.ne .Lnext_advance
    add x7, x7, #2
    cbnz w10, .Lnext_name
    ldr w7, [x5, #28]
    add x5, x5, x7
    sub w6, w6, #1
    b .Lnext_found
.Lnext_advance:
    ldr w7, [x5, #28]
    add x5, x5, x7
    sub w6, w6, #1
    b .Lnext_loop
.Lnext_found:
    cbz w6, .Lmissing
    ldr w8, [x5, #20]
    cmp x3, x8
    b.lo .Lnext_small
    str x8, [x0]
    ldp x9, x10, [x5]
    stp x9, x10, [x2]
    add x9, x5, #32
    mov x7, #0
.Lnext_bytes:
    cmp x7, x8
    b.hs .Lsuccess
    ldrb w10, [x9, x7]
    strb w10, [x1, x7]
    add x7, x7, #1
    b .Lnext_bytes
.Lnext_small:
    str x8, [x0]
    b .Lsmall
efivar_store_set:
    mov x0, #3
    b .Lerror
efivar_store_query:
    cbz x1, .Linvalid
    cbz x2, .Linvalid
    cbz x3, .Linvalid
    tst w0, #0xfffffff8
    b.ne .Lunsupported
    tbz w0, #1, .Linvalid
    adr x4, efivar_store_index
    ldr x4, [x4]
    cbz x4, .Lcorrupt
    validate_index x4, x5, w5, w6
    add x4, x4, #24
    tbnz w0, #0, .Lquery_copy
    add x4, x4, #24

.Lquery_copy:
    ldp x5, x6, [x4]
    ldr x7, [x4, #16]
    str x5, [x1]
    str x6, [x2]
    str x7, [x3]
.Lsuccess:
    mov x0, #0
    ret
.Lunsupported:
    mov x0, #3
    b .Lerror
.Lmissing:
    mov x0, #14
    b .Lerror
.Lsmall:
    mov x0, #5
    b .Lerror
.Linvalid:
    mov x0, #2
    b .Lerror
.Lcorrupt:
    mov x0, #33
.Lerror:
    mov x17, #0x8000000000000000
    orr x0, x0, x17
    ret
.balign 8
efivar_store_index:
    .quad 0
.Lindex_magic:
    .quad 0x3158444956524653
efivar_store_blob_end:
