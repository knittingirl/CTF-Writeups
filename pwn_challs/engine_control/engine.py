from pwnlib.tubes.process import *
from pwnlib.term.readline import *
from pwnlib.util import *
import sys
import string

l = tube()
l.send_raw = lambda x: (sys.stdout.buffer.write(x), sys.stdout.flush())
l.connected_raw = lambda d: True

p = process("./engine")

t = tube()
t.send_raw = lambda x: l.send(x)
t.connected_raw = lambda d: True
t.shutdown = lambda d: l.close()

p.connect_output(t)

while True:
    if not p.connected():
        l.close()

    inp = str_input()

    if any(c not in string.ascii_letters + string.digits + string.punctuation for c in inp):
        l.sendline("Invalid input.")
        p.sendline()
    else:
        p.sendline(inp)
