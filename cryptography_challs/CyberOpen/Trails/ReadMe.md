# Trails

### Acknowledgements: 
I did not solve this challenge during the live event, so I was able to benefit from a small amount of discussion that had occurred within the Discord immediately following the end of the challenge. Ratman's comments were particularly helpful in pointing me in the direction of differential trails. I also would like to credit the paper "A Tutorial on Linear and Differential Cryptanalysis" by Howard M. Heys for providing a lot of help in understanding this topic and giving me a verbal framework for key extraction.

This writeup also includes an alternate explanation at the end by sky/Teddy Heinen, who managed to sidestep a lot of the cryptographic concepts and extract the flag using the reverse-engineering Python module z3. Please read through to the end to see that!

The description for this challenge is as follows:

*Look! I wrote my own cryptographic code! I bet you can't recover the key. I even give you the source code! (service.py)*

*To get going, check out the attached PNG, and the sample output.txt that the python code generated when it still had the flag/key present. We'll accept the answer (flag/key) in binary, hex, or ascii.*

**TL;DR Solution:** Figure out that the challenge requires the use of differential trails and do research on the topic. Map out the differentials for the provided sboxes and a trail that spans three rounds, and test techniques on an edited script. Finally implement to recover the final round key, after which point the remaining round keys are simple to recover.

## Gathering Information

The challenge came with three files: service.py, output.txt, and SPN.png. Service.py is where we can see exactly how the algorithm is implemented, which is supplemented by a visual illustration in SPN.png. Basically, what we are looking at is a simple block cipher. The png file indicates that it follows the model of several rounds of XOR with a fresh subkey, run through a substitution box, or sbox, and scramble the bits within the block in a permutation. 

![image](https://user-images.githubusercontent.com/10614967/184306599-cfd5c5ef-950c-461d-a53d-b94d96c9b3f3.png)

If we look at the actual service.py program, we can see that it takes our input has hex, converts it into binary, then runs it through a blocks() function, and each block through an encrypt() function. Error handling for non-hex data is included.
```
try:
    m = binary(input("Enter message: "))
    print(''.join([encrypt(block) for block in blocks(m)]))
except:
    print('Invalid Input. Enter message in hex.')
```
The blocks function divides the input into 16-character chunks; in this case, since it's being fed binary strings, the result is a block-size of 16-bits, or 2 bytes.
```
def blocks(s):
    return [s[i:i+16].ljust(16, '0') for i in range(0, len(s), 16)]
```
Then there's the encrypt function itself. As expected, it seems to follow a pattern in which there are three rounds of XORing with a flag, running through an sbox, then a permutation, followed by a final round of XOR, sbox, and another XOR. The flag itself is a list of five 16-character inputs that seem to have been redacted (these should be binary strings, and will need to be filled in with 1's and 0's if you want to run the python script!). The sbox seems to be handled with a list where each number's transformed value is based on the value at the relevant index in the list; for example, an input of 1 would be transformed into a 5. The sboxes themselves are only 4 bits in size. Finally, the pbox/permutation works similarly to the sbox, but is run on every bit in the block rather than individually transforming 4-bit sections. 
```
sbox = [1, 5, 15, 2, 14, 8, 0, 9, 10, 3, 4, 12, 13, 7, 11, 6]

pbox = [0x00, 0x04, 0x08, 0x0c, 0x01, 0x05, 0x09, 0x0d,
        0x02, 0x06, 0x0a, 0x0e, 0x03, 0x07, 0x0b, 0x0f]

flag = ['################',
        '################',
        '################',
        '################',
        '################'] #READACTED
...
def encrypt(x):
    for i in range(4):
        x = xor(x, flag[i])
        x = ''.join([bin(sbox[int(x[i:i+4], 2)])[2:].zfill(4) for i in range(0, len(x), 4)])
        if i == 3:
            x = xor(x, flag[i + 1])
        else:
            x = ''.join([x[i] for i in pbox])
    return x
```
Finally, the output.txt file is a long list of sample inputs and outputs. If you divide each input up into 16-bit chunks, then every single possible 16-bit block has its ciphertext provided in the file. This should be helpful!
````
Enter message: 0000000100020003000400050006000700080009000a000b000c000d000e000f
1100111011010000100110111000010110111111010111100111000111100110111000111100011111001000011010011101101110101000011000000001111011100100111101011001100100110111001111001001100111111110000000000011000100100000100011100100011001010001101100000010010001111000
Enter message: 0010001100120013001400150016001700180019001a001b001c001d001e001f
0100111100000001011001100100111000000011111010101010001000010000000110001010000001010001000110111111100010101011000010010100010101101101111000010001110001111111010100010001110010111111000000010100111100001110101000100001111110111111000011101111110001111100
...
Enter message: fff0fff1fff2fff3fff4fff5fff6fff7fff8fff9fffafffbfffcfffdfffeffff
1100000000011110011100000111111001010100111111101000100110100011011100001000110101010110010111100001101110000011000111010111001110101001111101011010100110100101110010110011001111110011000111011010011011110101111110110011110101011111110001010011011010101101
````

Finally, in order to determine an appropriate cryptographic approach, you basically would have had to get lucky with Google or have pre-existing knowledge of differential trails. The main pointers were the title (Trails), and the characteristics of 16-bit block size and 4-bit sboxes; in particular, the paper "Key Dependency of Differentials: Experiments in the Differential Cryptanalysis of Block Ciphers Using Small S-boxes" by Howard M Heys provides a great indication that differential trails can be used here, since one of the paper's main examples of the technique uses a toy cipher with 16-bit block sizes and 4-bit sboxes.

## Differential Analysis Theory

### Differential Concepts

To begin with, we need to understand some of the general of differential analysis. Basically, a differential in cryptography means that for a pair of plaintexts P1 and P2, if you take their ciphertexts C1 and C2 (after a single round of block cipher), they will be statistically more likely to have certain ratios for (P1 XOR P2) / (C1 XOR C2). This property is helpful in a block cipher like this because the XORing ciphertexts together effectively nullifies the XOR with the round key, since x XOR x = 0. Differential trails are an extension of this concept across multiple rounds; the basic idea is to chain together high-probability differentials across rounds to get a highly likely plaintext-pair to ciphertext-pair ratio. To find these chains of differentials, we need to examine the cipher's sboxes and permutations, the characteristics of the cipher that will not be nulled out by the differential and that we have full knowledge of.

### Sbox Analysis and Finding Trails

The first step of our differential analysis takes place on the level of the 4-bit sboxes. Each sbox has 16 possible inputs. The idea here is to test each possible pair of plaintext inputs to the sbox function by finding their differential before and after encipherment. If certain differential pairs come up more frequently, then this provides a start for differential analysis. Here is a python script to find the differentials of all possible pairs of sbox inputs, excluding those with null differentials:
```
sbox = [1, 5, 15, 2, 14, 8, 0, 9, 10, 3, 4, 12, 13, 7, 11, 6]

diffs = []
for i in range(16):
    for j in range(16):
        if i != j:
            plain_diff = i ^ j
            enciphered_diff = sbox[i] ^ sbox[j]
            diffs.append(str(plain_diff) + ' => ' + str(enciphered_diff))

diffs_dict = {}

for item in diffs:
    if item not in diffs_dict.keys():
        diffs_dict[item]=1
    else:
        diffs_dict[item] += 1

print(dict(sorted(diffs_dict.items(), key=lambda item: item[1])))
```
And the results show that there are indeed some differentials that come up more frequently than others! In particular, plaintext differentials of 12 and 14 have 50% odds of producing ciphertext differentials of 4 and 10 respectively, and plaintext differentials of 2, 15, 6, 8, and 10 have 3/8 odds of producing ciphertext differentials of 14, 15, 1, 11, and 5 respectively. 
```
{'1 => 4': 2, '3 => 3': 2, '5 => 9': 2, '11 => 13': 2, '12 => 12': 2, '13 => 6': 2, '15 => 7': 2, '3 => 10': 2, '2 => 7': 2, '5 => 11': 2, '4 => 13': 2, '7 => 5': 2, '6 => 12': 2, '9 => 15': 2, '8 => 6': 2, '11 => 1': 2, '10 => 9': 2, '13 => 8': 2, '12 => 2': 2, '15 => 14': 2, '14 => 3': 2, '7 => 7': 2, '5 => 6': 2, '11 => 12': 2, '9 => 3': 2, '14 => 2': 2, '15 => 8': 2, '6 => 10': 2, '4 => 11': 2, '10 => 1': 2, '8 => 14': 2, '15 => 15': 2, '14 => 5': 2, '1 => 6': 2, '15 => 2': 2, '8 => 3': 2, '9 => 9': 2, '3 => 8': 2, '13 => 2': 2, '12 => 11': 2, '15 => 12': 2, '14 => 4': 2, '9 => 5': 2, '11 => 3': 2, '13 => 12': 2, '10 => 13': 2, '11 => 7': 2, '12 => 5': 2, '11 => 4': 2, '3 => 6': 2, '4 => 7': 2, '5 => 13': 2, '2 => 15': 2, '5 => 14': 2, '4 => 4': 2, '6 => 5': 2, '1 => 8': 2, '6 => 9': 2, '7 => 3': 2, '7 => 1': 2, '6 => 11': 2, '5 => 7': 2, '4 => 10': 2, '1 => 10': 2, '2 => 6': 2, '3 => 11': 2, '3 => 12': 2, '7 => 8': 4, '9 => 2': 4, '1 => 13': 4, '13 => 9': 4, '7 => 12': 4, '5 => 2': 4, '11 => 8': 4, '9 => 6': 4, '3 => 7': 4, '13 => 13': 4, '2 => 1': 4, '8 => 15': 4, '10 => 14': 4, '1 => 9': 4, '15 => 3': 4, '2 => 14': 6, '4 => 15': 6, '6 => 1': 6, '8 => 11': 6, '10 => 5': 6, '14 => 10': 8, '12 => 4': 8}
```
At this point, we have to trace out a trail of highly likely differentials, bearing permutations in mind for each. The idea here is to start with a plaintext differential in which one of sboxes has a value differential in the plaintext that is likely to have a specific differential once enciphered. For example, you could start with 0x8000 to provide the leftmost sbox an input differential of 0x8 and likely output differential of 0xb, or 0x0800 for similar for the sbox second to the left, etc.

The .png file provided with the challenge is actually really helpful here to trace out the permutations and keep track of our inputs as bits, and with some trial and error, I was able to find a trail with a probability of (1/2) * (3/8) ^ 4; the first round depends on the 12 => 4 differential, the second on the 8 => 11 differential, and the third on three sboxes with the 4 => 15 differential. Some general guidelines to find good trails is to try to use cipher differentials with as few bits as possible, since more bits will spread to more sboxes for the differential to depend upon, resulting in poorer results. This is why, for example, 12 => 4 (0b0100) made a better starting point than 14 => 10 (0b1010). Here is that trail fully traced out:

![image](https://user-images.githubusercontent.com/10614967/184410509-9db8d2cc-f8be-408c-a5ef-c1f4b3b4a384.png)

### Concept for Key Extraction

Now it's time to figure out how to use this information to actually extract keys! You may have noticed in the annotated diagram above, I did not carry my lines through the final round of sboxes. This is because at this point in the technique's implementation, the ciphertexts are partially decrypted to meet at this point. Basically, the idea is to take sample pairs of plaintexts with the desired initial differential, 0xc000 in our case, then take the ciphertexts, XOR each of them by a test key, run them backwards through the sbox function (the one used in the actual cryptographic protocol rather than the differentials), and then XOR them together at this point to see the differential. They should have an elevated likelihood of equalling the differential at that stage in the trail (in this case, just after the final permutation, which will be 0xbbbb as indicated in the diagram), if the key being used is correct. It is important to note here that any null sboxes at that stage in the trail would produce 4-bit gaps in the key, necessitating additional runs and trails, but that is not the case in the full implementation here. As a result, we can get the final round key by testing all plaintext pairs with the correct differential in this manner, and the keys that get the most hits as differential matches will be likely candidates. Once we have the final round key, we can keep moving up the trail in a similar fashion to get more keys, but now with higher certainty and even fewer computations.

## Differential Analysis Application

### Sample Test Case

In order to ensure that my interpretation of the paper was working, I devised a more basic implementation of the cipher with known keys and only one full round, followed by the partial non-permutation round. Basically, the test scenario will look like this:

![image](https://user-images.githubusercontent.com/10614967/184455174-2b65e84d-6283-4650-8a3b-75ed8e3743fe.png)

I also chose a much shorter test trail case, in which the plaintext difference should be 0xc000, and the ciphertext difference should be 0x0800 with odds of 50%.

![image](https://user-images.githubusercontent.com/10614967/184456450-152804f1-7618-4a9f-9028-fc8a2fd24f62.png)

Now we write python code! I ended up rewriting a fairly significant portion of the encryption function in order to make it operate mostly with integers for convenience and speed, in addition to reducing the size of the for loop to reduce the rounds, and I also had to write a fresh function to do the partial decryption. At this point, the decrypt function only XORs the test key with the ciphertext, then reverses it up through the sboxes once. Finally, I actually wrote a loop to test plaintexts with the appropriate differentials; note that if some of the sboxes are null, you can throw out differential pairs whose ciphertext differentials don't have nulls in the corresponding area (i.e. if leftmost sbox differential is null, the cipher differential must have 0s in its four leading bits). It is also important to note that key bits will only be recovered for sbox areas that are non-null; in this case, we are only expecting to recover the second most significant digit; in this case, it will be the 0x2 from 0x3234, which is the third and final round key in this scheme.

```
sbox = [1, 5, 15, 2, 14, 8, 0, 9, 10, 3, 4, 12, 13, 7, 11, 6]

sbox_rev = [6, 0, 3, 9, 10, 1, 15, 13, 5, 7, 8, 14, 11, 12, 4, 2]

pbox = [0x00, 0x04, 0x08, 0x0c, 0x01, 0x05, 0x09, 0x0d,
        0x02, 0x06, 0x0a, 0x0e, 0x03, 0x07, 0x0b, 0x0f]
        
flag = [0xc320, 0x4323, 0x3234, 0x4240, 0x5780]

def encrypt_custom(x):
    for i in range(0,2):

        x = x ^ flag[i]

        new_x = 0
        for j in range(3,-1,-1):
            sbox_bits = (x >> (j * 4)) % 0x10
            sbox_enc = sbox[sbox_bits]
            new_x += sbox_enc * (0x10 ** j)

        if i == 1:
            new_x = new_x ^ flag[i+1]

        else:
            new_x = int(''.join([format(new_x, '016b')[i] for i in pbox]), 2)

        x = new_x
    return new_x

def decrypt_end(x, final_key):
    x = x ^ final_key
    new_x = 0
    for j in range(3,-1,-1):
        sbox_bits = (x >> (j * 4)) % 0x10
        sbox_enc = sbox_rev[sbox_bits]
        new_x += sbox_enc * (0x10 ** j)
    return new_x

test_keys = {}

for i in range(0, 0xffff):
    pt1 = i
    pt2 = i ^ 0xc000
    if pt2 < pt1:
        continue
    ct1 = encrypt_custom(pt1)
    ct2 = encrypt_custom(pt2)
    pt_diff = pt1 ^ pt2
    ct_diff = ct1 ^ ct2
    if (ct_diff % 0x10000) // 0x1000 != 0:
        continue
    if (ct_diff % 0x100) // 0x10 != 0:
        continue
    if (ct_diff % 0x10) // 0x1 != 0:
        continue
    
    for key1 in range(0x10):
        partial_ct1 = decrypt_end(ct1, key1 * 0x100)
        partial_ct2 = decrypt_end(ct2, key1 * 0x100)
        ct_diff1 = partial_ct1 ^ partial_ct2

        key = key1 * 0x100
            
        if ct_diff1 == 0x800: 
            if hex(key) not in test_keys.keys():
                test_keys[hex(key)] = 1
            else:
                test_keys[hex(key)] += 1 

print(dict(sorted(test_keys.items(), key=lambda item: item[1])))
```
The script prints out all of the keys sorted by frequency with most frequent keys at the end. In this case, a 2 seems to appear most frequently, which is the digit we were hoping to obtain. The technique is a success!
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/CyberCombine$ python3 test_one_round.py
{'0x400': 2048, '0x100': 2048, '0x700': 4096, '0x800': 4096, '0x600': 4096, '0x900': 6144, '0x300': 8192, '0xd00': 8192, '0xc00': 10240, '0x200': 16384}
```

### Cracking the Key

#### The Final Round Key

Now I can try this process out on the actual output.txt file to see if I can recover the final round key. Since the full differential trail forces us to crack all 16 bits of the key simultaneously, the process will take a bit longer. In an effort to speed it up a bit and potentially eliminate false positives since the differential is potentially a little weak, I took steps to limit the tested keys to ASCII characters since the challenge description indicates that the flag does translate to printable ASCII. I also had to parse the output.txt file to create a dictionary of plaintext-ciphertext pairs. The relevant updated section is:
```
file = open('output.txt', 'r')
mappings = {}

while True:
    line = file.readline()
    if not line:
        break
    if 'Enter' in line:
        cleaned = line.split('message: ')[1].strip('\n')
        for i in range(16):
            plain = int(cleaned[i*4: i*4+4], 16)
            cipher = int(file.read(16), 2)
            mappings[plain] = cipher
test_keys = {}
start_time = time.time()

for i in range(0, 0xffff):
    pt1 = i
    pt2 = i ^ 0xc000
    if pt2 < pt1:
        continue
    ct1 = mappings[pt1]
    ct2 = mappings[pt2]
    pt_diff = pt1 ^ pt2
    ct_diff = ct1 ^ ct2 
    for char1 in string.printable:
        for char2 in string.printable:
            key = ord(char1) * 0x100 + ord(char2)
            partial_ct1 = decrypt_end(ct1, key)
            partial_ct2 = decrypt_end(ct2, key)
            ct_diff_decr = partial_ct1 ^ partial_ct2
                                
            if ct_diff_decr == 0xbbbb: 
                if hex(key) not in test_keys.keys():
                    test_keys[hex(key)] = 1
                else:
                    test_keys[hex(key)] += 1  
    if i % 0x20 == 0:
        print(hex(i))
        print(dict(sorted(test_keys.items(), key=lambda item: item[1])))

print(dict(sorted(test_keys.items(), key=lambda item: item[1])))

end_time = time.time()
print('The process took a total time of:', end_time - start_time)
```
The script will take a while to run, but after approximately 20 minutes, I got an output. Since 0x3f21 ('?!') and 0x3b21 (';!') appear with a reasonably similar frequency, it makes sense to consider both of them possible round keys, although the '?!' does seem like it would make more sense as the last two characters of a flag.
```
...
'0x7b21': 80, '0x3b61': 85, '0x3f61': 85, '0x3821': 98, '0x3f21': 141, '0x3b21': 156}

The process took a total time of: 1153.604120016098
```
#### The Fourth Round Key

Now we can adjust the algorithm and go for another round key in much the same manner as the first. I decided to initially assume that the final round key was actually 0x3f21, and adjusted my partial decryption function to XOR by the known-good final round key first, followed by a run up through the sbox, then an XOR by the guessed round key, a run through the permutation (this actually reverses itself when run again, so I did not have to write a separate permutation reverser), and a final run up through the sbox
```
key5 = 0x3f21

def decrypt_end(x, test_key):
    keys = [key5, test_key]
    for i in range(2):
        x = x ^ keys[i]
        new_x = 0
        if i >= 1:
            x = int(''.join([format(x, '016b')[i] for i in pbox]), 2)
        for j in range(3,-1,-1):
            sbox_bits = (x >> (j * 4)) % 0x10

            sbox_enc = sbox_rev[sbox_bits]

            new_x += sbox_enc * (0x10 ** j)
        
        x = new_x

    return x
```
Initially, I opted to follow the trail that I traced out earlier, provided below as a refresher. This fills three of the four sboxes, so an additional trail will need to be traced to get the second-to-left nibble.

![image](https://user-images.githubusercontent.com/10614967/184410509-9db8d2cc-f8be-408c-a5ef-c1f4b3b4a384.png)

So, here is the slightly refreshed for loop:
```
...
for j in range(0x8):
        for char2 in string.printable:
            key = j * 0x1000 + ord(char2)
            partial_ct1 = decrypt_end(ct1, key)
            partial_ct2 = decrypt_end(ct2, key)
            ct_diff_decr = partial_ct1 ^ partial_ct2
                                
            if ct_diff_decr == 0x4044: 
                if hex(key) not in test_keys.keys():
                    test_keys[hex(key)] = 1
                else:
                    test_keys[hex(key)] += 1  
...
```
And the end result isn't super definitive. Basically, two nibbles seem to be plausible for each of the nibbles that we're trying to crack, and we can wait to make
```
...
'0x3061': 288, '0x3065': 288, '0x3021': 288, '0x3025': 288, '0x7061': 288, '0x7065': 288, '0x7021': 288, '0x7025': 288
```
In order to definitively derive the fourth round key, I traced out a new trail as follows, which applies to all bytes:
![image](https://user-images.githubusercontent.com/10614967/184463894-409d36d9-3c92-40f9-9449-d63a7993e513.png)

The adjusted script is as follows; I am throwing out keys that do not follow the structure shown above in order to significantly improve the speed of the program:
```
for i in range(0, 0xffff):
    pt1 = i
    pt2 = i ^ 0x0c00
    if pt2 < pt1:
        continue
    ct1 = mappings[pt1]
    ct2 = mappings[pt2]
    pt_diff = pt1 ^ pt2
    ct_diff = ct1 ^ ct2 
    for char1 in string.printable:
        if (ord(char1) // 0x10) != 0x3 and (ord(char1) // 0x10) != 0x70:
            continue
        for char2 in ''.join([chr(0x21), chr(0x25), chr(0x61), chr(0x65)]):
            #key = j * 0x1000 + ord(char2)
            key = ord(char1) * 0x100 + ord(char2)
            partial_ct1 = decrypt_end(ct1, key)
            partial_ct2 = decrypt_end(ct2, key)
            ct_diff_decr = partial_ct1 ^ partial_ct2
            if ct_diff_decr == 0x4444: 
                if hex(key) not in test_keys.keys():
                    test_keys[hex(key)] = 1
                else:
                    test_keys[hex(key)] += 1  
```

The results show that the fourth round key is also 0x3f21, so the last four characters of the flag seem to be '?!?!'. This seems logical, so I don't see a need to test the 0x3b21 key.
```
...
{'0x3061': 1, '0x3161': 2, '0x3465': 3, '0x3565': 6, '0x3665': 7, '0x3261': 7, '0x3861': 8, '0x3461': 9, '0x3561': 10, '0x3661': 11, '0x3c65': 12, '0x3761': 14, '0x3765': 14, '0x3361': 14, '0x3961': 20, '0x3c61': 24, '0x3a61': 24, '0x3e65': 32, '0x3e61': 32, '0x3d65': 34, '0x3d61': 40, '0x3b61': 48, '0x3065': 55, '0x3f65': 64, '0x3f61': 64, '0x3025': 94, '0x3425': 110, '0x3865': 132, '0x3265': 135, '0x3021': 145, '0x3165': 148, '0x3825': 220, '0x3225': 242, '0x3c25': 248, '0x3125': 252, '0x3625': 258, '0x3525': 272, '0x3a65': 328, '0x3821': 348, '0x3365': 350, '0x3421': 354, '0x3221': 354, '0x3965': 360, '0x3121': 378, '0x3a25': 584, '0x3925': 606, '0x3e25': 616, '0x3325': 640, '0x3d25': 642, '0x3725': 668, '0x3b65': 848, '0x3c21': 864, '0x3a21': 864, '0x3921': 912, '0x3621': 936, '0x3321': 936, '0x3521': 948, '0x3b25': 1552, '0x3f25': 1616, '0x3e21': 2304, '0x3b21': 2304, '0x3d21': 2304, '0x3721': 2496, '0x3f21': 6144}
The process took a total time of: 47.839231729507446
```

#### Finishing up the Round Keys

The other keys were ultimately recovered in a similar fashion. Here is the script to recover the full third round key all in one go; I will note here that the script does take a while to run and attempts were made to reduce the search space, but they ultimately weren't working out, while this script at least ultimately returns the round key successfully. Here is the trail used:

![image](https://user-images.githubusercontent.com/10614967/184498561-24279df1-cb0e-426d-b601-f8a43eefd4f2.png)

And the relevant subsection of the script. I actually ended up cutting it short at around i = 0x2000 since it was likely to take an extremely long time, and at that time, I had a clear leader that had remained consistent for some time. I believe that fewer test cases are needed at the higher rounds since the trails have stronger probabilities (i.e. this one should be at 6/16), and there should be fewer alternative trails that hit the same result.
```
for i in range(0, 0xffff):
    pt1 = i
    pt2 = i ^ 0x4000
    if pt2 < pt1:
        continue
    ct1 = mappings[pt1]
    ct2 = mappings[pt2]
    pt_diff = pt1 ^ pt2
    ct_diff = ct1 ^ ct2 
    for char1 in string.printable:
        for char2 in string.printable:
            key = ord(char1) * 0x100 + ord(char2)
            partial_ct1 = decrypt_end(ct1, key)
            partial_ct2 = decrypt_end(ct2, key)
            ct_diff_decr = partial_ct1 ^ partial_ct2
            if ct_diff_decr == 0x8888: 
                if hex(key) not in test_keys.keys():
                    test_keys[hex(key)] = 1
                else:
                    test_keys[hex(key)] += 1  
    if i % 0x20 == 0:
        print(hex(i))
        print(dict(sorted(test_keys.items(), key=lambda item: item[1])))
```
The third round key was ultimately 0x6c33, which corresponds with 'l3', so the final six characters of the flag are 'l3?!?!'
```
...
'0x6c3b': 2048, '0x6c37': 2048, '0x2877': 2048, '0x6c31': 2048, '0x6c32': 2048, '0x7d22': 2048, '0x2873': 2560, '0x7d23': 2560, '0x6c33': 4096}
```
Then getting the second round key was pretty simple; the next round of decryption brings the ratio up through the first sbox, so we are simply looking for plaintext and ciphertext differentials that match. As for the third round key, I cut the script off early; I walked away for a bit and ended up at around i = 0x680. The second round key is 0x6d70, making the final 8 characters of the flag 'mpl3?!?!'
```
'0x4f50': 448, '0x6970': 512, '0x6f70': 625, '0x7c61': 636, '0x7d60': 636, '0x7d61': 636, '0x6c70': 636, '0x4d50': 640, '0x4d52': 656, '0x4f52': 656, '0x6d74': 768, '0x2930': 768, '0x2934': 768, '0x2d34': 1024, '0x6d70': 1697}
```
Finally, the first round key is really trivial at this point, since we can do a partial decryption all the way up to the XOR with the round keys we already have, then just XOR that result with the plaintext to get the key. I did it with two sample plaintexts to ensure I got consistent results:
```
key5 = 0x3f21
key4 = 0x3f21
key3 = 0x6c33
key2 = 0x6d70

def decrypt_end(x):
    keys = [key5, key4, key3, key2]
    for i in range(4):
        x = x ^ keys[i]
        new_x = 0
        if i >= 1:
            x = int(''.join([format(x, '016b')[i] for i in pbox]), 2)
        for j in range(3,-1,-1):
            sbox_bits = (x >> (j * 4)) % 0x10

            sbox_enc = sbox_rev[sbox_bits]

            new_x += sbox_enc * (0x10 ** j)
        
        x = new_x

    return x
...
pt = 0
ct = mappings[pt]
partial = decrypt_end(ct)

print(hex(partial ^ pt))
pt = 0x100
ct = mappings[pt]
partial = decrypt_end(ct)

print(hex(partial ^ pt))
```
And I got a result of 0x7331. This gives us a final flag of 's1mpl3?!?!', and the challenge is complete.

Thanks for reading!

## Z3-Approach by Sky/Teddy Heinen

I don't know cryptography so I immediately jumped for my beloved z3. Although the model came together without too much trouble, I realized that it wouldn't work as-is because a single block did not contain enough information to accurately reverse the flag/key. Although I could safely assume that combining every block in the output would be sufficient to reverse the key, this was too much information for z3 to handle (i walked off and got food and it didn't finish idk when it would have). My hope was that a subset of the block pairs would be sufficient to reverse the key. I tried a number of strategies to pick this subset. 

* add a block at a time in order -- this did not work; constraint set grew too fast and slowed down before the flag could be found
* add a block at a time in order, popping off new constraints if it did not give us a different flag -- this did not work; not sure why but it still slowed down too fast
* adding blocks in a random order and praying i got them in an order that worked -- this ended up being the strategy i used to get the flag.  tl;dr just get lucky lol

```
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
```

