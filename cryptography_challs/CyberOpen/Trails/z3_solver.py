#Full credit for writing this script goes to sky/Teddy Heinen
from z3 import *
import time
from random import shuffle,seed
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def flatten(l):
    return [item for sublist in l for item in sublist]

def binary(hex):
    return bin(int(hex, 16))[2:].zfill(len(hex) * 4)

c_sbox = [1, 5, 15, 2, 14, 8, 0, 9, 10, 3, 4, 12, 13, 7, 11, 6]

pbox = [0x00, 0x04, 0x08, 0x0c, 0x01, 0x05, 0x09, 0x0d,
        0x02, 0x06, 0x0a, 0x0e, 0x03, 0x07, 0x0b, 0x0f]

sbox = Array("sbox", BitVecSort(4), BitVecSort(4))

set_param("parallel.enable", True)

s = Solver()

for i in range(16):
	s.add(sbox[i] == c_sbox[i])

flag = [[BitVec(f"flag_{x}_{y}", 1) for x in range(16)] for y in range(5)]


for j in range(5): # flag is known to be ASCII
	s.add(flag[j][0] == 0)
	s.add(flag[j][8] == 0)

# for i in range(16):
# 	for j in range(5):
# 		s.add(flag[j][i] == 1)

def add_block(s, in_block, out_block, ctr):

	init_state = [BitVec(f"init_stage_{x}_{ctr}", 1) for x in range(16)]
	fin_state = [BitVec(f"fin_stage_{x}_{ctr}", 1) for x in range(16)]

	"""
	 transposes 4 1-bit BitVecs into a 4-bit BitVec
	 1,0,1,0 becomes 0b1010
	"""
	def p4(a,b,c,d):
		return Concat(a,b,c,d)

	"""
	tranposes 1 4-bit BitVec into 4 1-bit BitVecs
	0b1010 becomes 0,1,0,1
	"""
	def u4(x):
		return Extract(3,3,x), Extract(2,2,x), Extract(1,1,x), Extract(0,0,x)

	def stage(idx, prev_state):
		next_stage = []
		for i in range(16):
			next_stage.append(prev_state[i] ^ flag[idx][i])
		stage_2 = [sbox[p4(a,b,c,d)] for a,b,c,d in chunks(next_stage,4)]
		stage_2 = flatten([u4(x) for x in stage_2])
		if idx == 3:
			stage_3 = [x ^ flag[idx+1][i] for i, x in enumerate(stage_2)]
		else:
			stage_3 = [stage_2[i] for i in pbox]
		return stage_3

	for idx, x in enumerate(in_block):
		s.add(init_state[idx] == int(x))


	second_stage = stage(0, init_state)
	third_stage = stage(1, second_stage)
	fourth_stage = stage(2, third_stage)
	fifth_stage = stage(3, fourth_stage)

	for idx in range(16):
		s.add(fifth_stage[idx] == int(out_block[idx]))

with open("output.txt") as f:
	lines = [x.rstrip() for x in f.readlines()]

ctr = 0
g = 0
start = time.time()


order = list(range(0,8192,2))
shuffle(order)
for i in order:
	print(f"checking idx[{i}]... {time.time()-start} since start")

	inp = binary(lines[i].split(": ")[1])
	outp = lines[i+1]

	for in_block, out_block in zip(chunks(inp, 16), chunks(outp, 16)):
		add_block(s, in_block, out_block, ctr)
		ctr += 1
	s.push()
	# hit that low-hanging fruit optimization
	# push forces z3 to use a solver which can be done incrementally which allows me to add additional constraints (new block pairs) and solve without redoing work
	if s.check() == sat:
		model = s.model()
		trial_flag = "".join(["".join([str(model[flag[y][x]].as_long()) for x in range(16)]) for y in range(5)])
		ascii_flag = "".join([chr(int(x,2)) for x in chunks(trial_flag, 8)]).encode()
		print(f"best guess for flag is {ascii_flag}")
	else:
		print("unsat :(")