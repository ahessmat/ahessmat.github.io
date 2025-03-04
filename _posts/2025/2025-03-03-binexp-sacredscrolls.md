---
title: Binary Exploitation Writeup - Regularity
published: true
date: 2025-02-25 00:00:00 +/-0000
categories: [general,ctf]
tags: [ctf,htb,binexp,binary exploitation,reverse engineering]     # TAG names should always be lowercase
image:
    path: /assets/images/malware.jpg
---

Running the program through `checksec` shows:

| Check Performed | Impact |
|--|--|
| <span style="color:green">Full RELRO</span>| Cannot target GOT. |
| <span style="color:red">No Canary Found</span>| Permits us to overflow RET addresses, if need be. |
| <span style="color:green">NX enabled</span>| Prevents us from injecting shellcode to the stack. |
| <span style="color:red">No PIE</span>| Binary addresses aren't randomized at runtime, making it easier to perform targeted jumps. |

Here's the decompiled `main()` function from `ghidra`:

```c
void main(void)

{
  undefined8 *puVar1;
  long lVar2;
  byte bVar3;
  undefined auStack_708 [1528];
  undefined8 uStack_110;
  undefined8 local_108;
  undefined8 local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined *local_40;
  undefined8 local_38;
  undefined4 local_2c;
  
  bVar3 = 0;
  uStack_110 = 0x400efa;
  setup();
  uStack_110 = 0x400eff;
  banner();
  uStack_110 = 0x400f09;
  clean();
  uStack_110 = 0x400f1a;
  printf("\nEnter your wizard tag: ");
  local_2c = 0x600;
  local_38 = 0x5ff;
  local_40 = auStack_708;
  read(0,auStack_708,0x5ff);
  printf("\nInteract with magic library %s",local_40);
  puVar1 = &local_108;
  for (lVar2 = 0x19; lVar2 != 0; lVar2 = lVar2 + -1) {
    *puVar1 = 0;
    puVar1 = puVar1 + (ulong)bVar3 * -2 + 1;
  }
  while( true ) {
    while (lVar2 = menu(), lVar2 == 2) {
      puVar1 = (undefined8 *)spell_read();
      local_108 = *puVar1;
      local_100 = puVar1[1];
      local_f8 = puVar1[2];
      local_f0 = puVar1[3];
      local_e8 = puVar1[4];
      local_e0 = puVar1[5];
      local_d8 = puVar1[6];
      local_d0 = puVar1[7];
      local_c8 = puVar1[8];
      local_c0 = puVar1[9];
      local_b8 = puVar1[10];
      local_b0 = puVar1[0xb];
      local_a8 = puVar1[0xc];
      local_a0 = puVar1[0xd];
      local_98 = puVar1[0xe];
      local_90 = puVar1[0xf];
      local_88 = puVar1[0x10];
      local_80 = puVar1[0x11];
      local_78 = puVar1[0x12];
      local_70 = puVar1[0x13];
      local_68 = puVar1[0x14];
      local_60 = puVar1[0x15];
      local_58 = puVar1[0x16];
      local_50 = puVar1[0x17];
      local_48 = puVar1[0x18];
      printf(&DAT_00401f80,&local_108);
    }
    if (lVar2 == 3) break;
    if (lVar2 == 1) {
      spell_upload();
    }
  }
  spell_save(&local_108);
                    /* WARNING: Subroutine does not return */
  exit(0x16);
}
```

At a high-level, this program drops us into a menu loop after performing some initial ASCII art with calls to `setup()`, `banner()`, and `clean()`. We also set a kind of "wizard tag" (`auStack_708`) using `read()`. At-a-glance, the menu affords us 3 options:

* The first (menu option `1`) makes a call to `spell_upload()`.
* The second (menu option `2`) makes a call to `spell_read()`; that function returns a string whose composition sets a bunch of other variables.
* The third (menu option `3`) makes a call to `spell_save()`.

So besides what's in `main()`, there's also some interesting functions in `spell_read()`, `spell_upload()`, and `spell_save()` to check out.

# Other Functions

## spell_read()

```c
char * spell_read(void)

{
  int iVar1;
  char *__s1;
  FILE *__stream;
  
  __s1 = (char *)malloc(400);
  system("unzip spell.zip");
  __stream = fopen("spell.txt","rb");
  if (__stream == (FILE *)0x0) {
    printf("%s\n[-] There is no such file!\n\n",&DAT_0040127f);
                    /* WARNING: Subroutine does not return */
    exit(-0x45);
  }
  fread(__s1,399,1,__stream);
  iVar1 = strncmp(__s1,&DAT_00401322,4);
  if (iVar1 == 0) {
    iVar1 = strncmp(__s1 + 4,&DAT_00401327,3);
    if (iVar1 == 0) {
      close((int)__stream);
      return __s1;
    }
  }
  printf("%s\n[-] Your file does not have the signature of the boy who lived!\n\n",&DAT_0040127f);
                    /* WARNING: Subroutine does not return */
  exit(0x520);
}
```

This function makes a `system()` call to unzip a local `spell.zip` archive, then reads data in from a `spell.txt` file within the archive. Assuming these files exist, it then reads in the magic bytes from `spell.txt` and checks them against the bytes:

`0xf09f919300e29aa1`

These bytes - it turns out - are not arbitrary, serving as emojis:

```python
from pwn import *
val = b'\xf0\x9f\x91\x93\x00\xe2\x9a\xa1'
print(val.decode())
```
:eyeglasses: \x00 &#9889;