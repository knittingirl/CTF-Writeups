The idea here is to keep a selection of ELF interpreters and libcs to avoid running specific virtual machines or docker instances as much as possible when a custom libc is required for a pwn challenge.

I believe I took most of these from my own VMs, but the 2.34 ones are from DiceCTF 2022's BabyRop challenge.

To use, I would recommend you first copy the binary that you want to run with a specific libc version.

Move the interpreter file (ld-...) to the same directory, and be sure to set its privileges to executable.

Then patch the copied binary with something like
```
patchelf my_binary --set-interpreter ../../ld-2.27.so --set-rpath ./
```
Use the libc file of your choice through pwntools by setting the LD_PRELOAD environment variable like so:
```
target = process('./my_binary', env={"LD_PRELOAD":"./libc.so.6"})
```
Or on the command line:
```
LD_PRELOAD=libc.so.6 ./my_binary
```
Or you can dispense with the need for LD_PRELOAD entirely with patchelf and the replace-needed option:
```
patchelf my_binary --replace-needed libc.so.6 libc-2.27.so
```
