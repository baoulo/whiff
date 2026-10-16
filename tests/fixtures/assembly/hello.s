# Hello world, x86-64 Linux (GNU as)
    .section .data
msg:
    .ascii "Hello, harbour\n"
    .section .text
    .globl _start
_start:
    mov $1, %rax        ; write
    mov $1, %rdi
    lea msg(%rip), %rsi
    mov $15, %rdx
    syscall
    mov $60, %rax
    xor %rdi, %rdi
    syscall
