# Pierated Art

### Automated Reverse-Engineering of a Picture

The description for this challenge is as follows:

![image](https://user-images.githubusercontent.com/10614967/182260224-43b4d243-4fe1-4c4d-a071-979324bec7d0.png)

*"Composition with Red, Yellow, and Blue by Piet Mondrian, with red graffiti all over it"*

*Downloaded some art from a sketchy torrent provider (piet_pirate), and there are scribbles all over it.*

*Update: The passwords (not the flag) are in lowercase ASCII*

*Challenge sponsored by Battelle*

*author: spicypete, richyliu*

This challenge was worth 311 points at the end of the competition, and it had a total of 24 solves. This was a pretty novel reverse engineering challenge that involved the use of PietCode, and while I don't think it was actually super hard with the appropriate tooling, it was definitely fun!

**TL;DR Solution:** Decode one of the base64 strings you get from the netcat connection and note that it is a png file with some random-looking primary color blocks scattered throughout. Based on name and appearance, run it as Pietcode with npiet and note that it is asking for a flag. Extract the plaintext version of the code with the -t flag to determine the flag that the program is asking for, since each character effectively needs to equal 0 modulo 26 when added to some number. Then figure out how to automate the predictable reverse-engineering process by writing python that extracts the relevant lines of Piet code for simple analysis, and run this against the remote server to get the flag.

## Gathering Information

This challenge only came with a netcat connection, so it makes sense to start investigating there! The challenge indicates a total of 10 stages, in which a lengthy base64 string is provided and a flag is requested. 
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/UIUCTF22$ nc pierated-art.chal.uiuc.tf 1337
== proof-of-work: disabled ==
Torrented Picture Data (Base64):
iVBORw0KGgoAAAANSUhEUgAAAyYAAAQACAIAAACbB9rAAAEAAElEQVR4nOz9d5gcx3UujJ/TPXl2dmczFsBG7CIQORAgIZIAc5BISsyUJQfZsi0HOVzf/D333u/73etr32tJtmxZycqSZQWKpEiREkmRAHNEztiEzXnC7k6eOr8/OlWHmZ0NWIBgvQ8fYra3uqq6urbrnfc9dRoPwAEA2HdgH+wHOHDwIOzbvx/oABzcB/sBAOEAwT44CLAfAQhMvyhYBvYfPAj7gHD/QTiw/8C+AwD79h/EA/th34EDsA8O4v79cODAgX37AKxl9h2Ag/v37dMaIsCDBw/s27cPEYhAQEBAYKGgBT1DEHHJ
...
/ccQGkBgFMDkgsAXAHoyC4MKC0AcA1AcgGASwE92pUAsQUArgRsaw0ALgXsnO0awJ7TAOB6gJcLAFwZ6ODOBcgsAHBhQHIBQI8AerojA0oLAHoCILkAoAcB/d3RALEFAD0HkFwA0BOBjt+9gNICgB4IpM8DQE8EsrO7hsbSFu48APRYwMsFAAA4vTodkFkAAIDkAgCgARgNOgMQWwAAYEByAQBgDwwL7QeUFgAAdoDkAgCgaWBwaBsgtgAAaBKQXAAAPAYYJVoDKC0AAFoGJBcAAK0CxormALEFAEBrAMkFAMCTYTdocBzXEzRH48vsCVcNAEAHApILAIA20jNHD1BaAAC0DZBcAAC0i54zhoDYAgCgPYDkAgCgY3DVwQSUFgAAHQJILgAAOhJXGlJAbAEA0IGA5AIAoFNw3rEFlBYAAJ0BbGsNAECn0OT+zQ6lw2DPaQAAuhLwcgEA0BU48lADMgsAgC4AJBcAAF2How04ILYAAOgyQHIBANANdO/IA0oLAICuByQXAADdSVcOQaC0AADoRkByAQDQ/XT2QARiCwCAbgckFwAADkTHjkigtAAAcBxAcgEA4HC0f1wCsQUAgKMBkgsAAMflSQcoUFoAADgsILkAAHB0WjNMgdgCAMDB+f8BNa+xgzH3mPUAAAAASUVORK5CYII=
Enter flag #1/10 (15s):aaaaaaaaaaaa
Incorrect!
```
If I decode the string and save it as a png file, the result looks something like this:
![image](https://raw.githubusercontent.com/knittingirl/Pre-Published-Writeups/main/reversing_challs/UIUCTF22/Pierated%20Art/piet_flag_piet.png?token=GHSAT0AAAAAABSGF7XOGY7G3QSJNTGSCIDUYXILYDQ)
The image looks mostly normal, but with some blocks of bright colors interspersed throughout. This, combined with challenge's title and description, strongly indicates that Piet code is being used here. To provide some context, Piet code is one of the few esolangs that is represented through visual image data, and Piet code images are visually based on the work of Piet Mondrian. 

To check if this is actually Piet, the lowest effort solution is to use a web interpreter. The main web interpreter is available here: http://www.bertnase.de/npiet/npiet-execute.php And the results of running the sample image through that tool indicates that a program asking for a flag to be entered, so the next step is to find the flag!

![image](https://user-images.githubusercontent.com/10614967/182261258-f20d8c23-f760-49f7-bd52-f8ae562c6bd8.png)

## Manually Extracting a Flag

In order to get a better look at how the code is interpreted and hopefully reverse engineer the desired flag, I downloaded npiet.c, linked here: http://www.bertnase.de/npiet/ The c file compiled pretty easily on Linux with gcc, but I did find that it required a .ppm file be fed into it in order to work. Fortunately, convert from the ImageMagick package can do these conversions easily, and I can have a better look at how the program works.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/UIUCTF22$ convert piet_sample.png piet_sample.ppm
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/UIUCTF22$ ./npiet piet_sample.ppm
enter flag:? aaaaaaaaaaaaaa
? ? ? 0
```
Eventually, I realized that I could use the "-t" flag to get a dump of how the pixels are being interpreted in more readily readable terms. This includes both assembly-like instructions such as push and multiply, as well as traces of a "stack"'s values at any given instruction:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/UIUCTF22$ ./npiet piet_sample.ppm -t

trace: step 0  (0,0/r,l dM -> 2,0/r,l lM):
action: push, value 8
trace: stack (1 values): 8

trace: step 1  (2,0/r,l lM -> 3,0/r,l nM):
action: push, value 4
trace: stack (2 values): 4 8

trace: step 2  (3,0/r,l nM -> 4,0/r,l lR):
action: multiply
trace: stack (1 values): 32

trace: step 3  (4,0/r,l lR -> 5,0/r,l lB):
action: duplicate
trace: stack (2 values): 32 32

trace: step 4  (5,0/r,l lB -> 6,0/r,l nB):
action: push, value 3
trace: stack (3 values): 3 32 32
```
My input from the terminal is initially requested at line 58 with an "in(char)" instruction. This appears to only request a single character, but it is later repeated several more times; later analysis showed that characters input first got pushed further back on the stack. I input a bunch of a's here:
```
trace: step 57  (55,3/l,l lR -> 54,3/l,l nY):
action: sub
trace: stack (2 values): 4 96

trace: step 58  (54,3/l,l nY -> 53,3/l,l nR):
action: in(char)
?
```
Once all of my a's had been loaded onto the stack, I was able to view a fairly predictable pattern in the disassembly, where a value like 14 is pushed onto the stack next to one of my input characters, and it is added to the numeric representation of that character ('a' = 97 in ascii). Then 26 is pushed onto the stack, and the sum from the previous step is moduloed by 26. Not is then performed on the result, which always result in a 0 unless a 0 is originally fed in. The result is then multiplied with the next number on the stack, typically 1.
```
trace: step 116  (520,612/d,l nC -> 520,614/d,l dC):
action: push, value 2
trace: stack (7 values): 2 1 97 97 97 97 96

trace: step 117  (520,614/d,l dC -> 520,615/d,l lC):
action: push, value 1
trace: stack (8 values): 1 2 1 97 97 97 97 96

trace: step 118  (520,615/d,l lC -> 520,616/d,l nY):
action: roll
trace: stack (6 values): 97 1 97 97 97 96

trace: step 119  (520,616/d,l nY -> 520,618/d,l dY):
action: push, value 14
trace: stack (7 values): 14 97 1 97 97 97 96

trace: step 120  (520,618/d,l dY -> 520,619/d,l dG):
action: add
trace: stack (6 values): 111 1 97 97 97 96

trace: step 121  (520,619/d,l dG -> 520,621/d,l lG):
action: push, value 26
trace: stack (7 values): 26 111 1 97 97 97 96

trace: step 122  (520,621/d,l lG -> 520,622/d,l nB):
action: mod
trace: stack (6 values): 7 1 97 97 97 96

trace: step 123  (520,622/d,l nB -> 520,623/d,l lR):
action: not
trace: stack (6 values): 0 1 97 97 97 96

trace: step 124  (520,623/d,l lR -> 520,624/d,l dY):
action: multiply
trace: stack (5 values): 0 97 97 97 96
trace: entering white block at 520,987 (like the perl interpreter would)...
```
At the end of the program, a number is output, which seems to be 0 for my incorrect guess. That 0 seems to be a direct result of one or more characters that produced a zero following the modulus operation. As a result, it seems worth trying characters that would not, in fact, produce zeroes for their respective modular operations.
```
trace: step 153  (246,167/r,r dY -> 247,167/r,r dG):
action: add
trace: stack (3 values): 115 0 96

trace: step 154  (247,167/r,r dG -> 249,167/r,r lG):
action: push, value 26
trace: stack (4 values): 26 115 0 96

trace: step 155  (249,167/r,r lG -> 250,167/r,r nB):
action: mod
trace: stack (3 values): 11 0 96

trace: step 156  (250,167/r,r nB -> 251,167/r,r lR):
action: not
trace: stack (3 values): 0 0 96

trace: step 157  (251,167/r,r lR -> 252,167/r,r dY):
action: multiply
trace: stack (2 values): 0 96

trace: step 158  (252,167/r,r dY -> 254,167/r,r lR):
action: out(number)
0
trace: stack (1 values): 96
```
So, the first character (technically the last character), has 14 added to it, is moduloed by 26, then notted. We can rephrase this as an algebra equation with (x + 14) % 26 = 0, and since we know the acceptable range of characters is lowercase ascii, we can calculate by hand or with a python loop that it must be the letter 't'. If we continue this line of logic with the other characters, we get 'e', 'i', and 'p' for a flag of 'piet'. If we input that when running the program, the program's final output is 1, which presumably means success!
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/UIUCTF22$ ./npiet piet_sample.ppm
enter flag:? piet
? ? ? 1
```
## Automating Analysis

So, now we know how to get individual flags, we need to start auto-analyzing them since the images served through the netcat connection change every time. The main factor that changes with each character/image is the numbers to be pushed just before the add. This means that if I can just extract these numbers, I can make the calculations to get the flag. 

If I try grepping on npiet with -t in use, I can see that 
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/UIUCTF22$ ./npiet piet_sample.ppm -t | grep 'push\|add'
action: push, value 8
action: push, value 4
action: push, value 3
action: push, value 5
action: add
action: push, value 14
action: add
action: push, value 20
action: add
action: push, value 5
action: add
action: push, value 18
action: add
action: push, value 2
...
action: push, value 14
action: add
action: push, value 26
action: push, value 2
action: push, value 1
action: push, value 3
action: add
action: push, value 26
action: push, value 2
action: push, value 1
action: push, value 25
action: add
action: push, value 26
action: push, value 2
action: push, value 1
action: push, value 18
action: add
action: push, value 26
```
So, in my python code, I:

1. Set up to automatically extract and save the png file file from the netcat connection.

2. Convert the png file to a ppm file and run the result through npiet with the -t flag, saving the text result.

3. Cut the result off at the last question mark to avoid the push-add combinations used to print the text at the beginning.

4. Create a list of numbers based on only push lines that come before add lines.

5. Derive the letters from the added numbers and squidge them together into a flag.

6. Send the results in a netcat connection, repeat ten times to get the flag.

The final, full python code looks like this:
```
from pwn import *
import base64
import os 
import string

def extract_flag(test_file):

    os.system('convert ' + test_file + '.png ' + test_file + '.ppm')

    target = process(['./npiet', '-t', test_file + '.ppm'])

    target.sendline(b'a' * 100)

    raw = target.recvall(timeout = 1)
    
    reduced = raw.split(b'?')[-1]
    lines = reduced.split(b'\n')
    reduced_lines = []
    for line in lines:
        if b'add' in line or b'push' in line:
            reduced_lines.append(line)
   
    desired_pushes = []
    nums = []
    for i in range(len(reduced_lines)):
        if b'add' in reduced_lines[i]:
            push_line = reduced_lines[i-1]
            nums.append(push_line.split(b' ')[-1])
    print(nums)
    
    flag = ''

    for num in nums:
        for i in range(4, 6):
            attempt = chr(26 * i - int(num))
            if attempt in string.ascii_lowercase:
                break
        flag = attempt + flag
    print(flag)
    return flag

target = remote('pierated-art.chal.uiuc.tf', 1337)

for i in range(10):
    file1 = open('pierated.png', 'wb')
    print(target.recvuntil(b'(Base64):\n'))
    result = target.recvuntil(b'Enter').replace(b'\nEnter', b'')

    decoded = base64.b64decode(result)
    file1.write(decoded)
    file1.close()
    payload = extract_flag('pierated')

    target.sendline(payload)

target.interactive()
```
And the end of the results looks like this:
```
b' flag #8/10 (15s):Correct!\nTorrented Picture Data (Base64):\n'
[+] Starting local process './npiet': pid 31649
[+] Receiving all data: Done (28.56KB)
[*] Process './npiet' stopped with exit code 0 (pid 31649)
[b'20', b'7', b'25', b'16', b'4', b'20', b'19', b'21']
mondrian
b' flag #9/10 (15s):Correct!\nTorrented Picture Data (Base64):\n'
[+] Starting local process './npiet': pid 31654
[+] Receiving all data: Done (31.72KB)
[*] Process './npiet' stopped with exit code 0 (pid 31654)
[b'14', b'4', b'20', b'7', b'16', b'6', b'21', b'3', b'16']
rembrandt
[*] Switching to interactive mode
 flag #10/10 (15s):Correct!
i'll just use google images next time :D
uiuctf{m0ndr14n_b3st_pr0gr4mm3r_ngl}
[*] Got EOF while reading in interactive
$
```
Thanks for reading!
