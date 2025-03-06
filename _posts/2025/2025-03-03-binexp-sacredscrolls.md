---
title: "Binary Exploitation Writeup - Sacred Scrolls: Revenge"
published: false
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
This outputs emojis like: &#128374; \x00 &#9889; (alluding the binary's overall theme: Harry Potter).

## spell_upload()

```c

/* WARNING: Type propagation algorithm not settling */

void spell_upload(void)

{
  char cVar1;
  long lVar2;
  ulong uVar3;
  undefined8 *puVar4;
  undefined4 *puVar5;
  byte bVar6;
  undefined auStack_1230 [8];
  undefined local_1228 [15];
  undefined8 uStack_1219;
  undefined2 auStack_1211 [2036];
  char cStack_229;
  undefined8 local_228 [65];
  FILE *local_20;
  ulong local_18;
  ulong local_10;
  
  bVar6 = 0;
  puVar4 = local_228;
  for (lVar2 = 0x40; lVar2 != 0; lVar2 = lVar2 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  puVar4 = (undefined8 *)local_1228;
  for (lVar2 = 0x200; lVar2 != 0; lVar2 = lVar2 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  auStack_1230 = (undefined  [8])0x400aa5;
  printf("\n[*] Enter file (it will be named spell.zip): ");
  auStack_1230 = (undefined  [8])0x400abe;
  local_18 = read(0,local_228,0x1ff);
  *(undefined *)((long)local_228 + (local_18 - 1)) = 0;
  for (local_10 = 0; local_10 < local_18; local_10 = local_10 + 1) {
    if (((((*(char *)((long)local_228 + local_10) < 'a') ||
          ('z' < *(char *)((long)local_228 + local_10))) &&
         ((*(char *)((long)local_228 + local_10) < 'A' ||
          ('Z' < *(char *)((long)local_228 + local_10))))) &&
        ((((*(char *)((long)local_228 + local_10) < '0' ||
           ('9' < *(char *)((long)local_228 + local_10))) &&
          (*(char *)((long)local_228 + local_10) != '.')) &&
         ((*(char *)((long)local_228 + local_10) != '\0' &&
          (*(char *)((long)local_228 + local_10) != '+')))))) &&
       (*(char *)((long)local_228 + local_10) != '=')) {
      auStack_1230 = (undefined  [8])0x400bea;
      printf("\n%s[-] File contains invalid charcter: [%c]\n",&DAT_0040127f,
             (ulong)(uint)(int)*(char *)((long)local_228 + local_10));
                    /* WARNING: Subroutine does not return */
      auStack_1230 = (undefined  [8])0x400bf4;
      exit(0x14);
    }
  }
  local_1228._0_4_ = 0x6f686365;
  local_1228._4_2_ = 0x2720;
  local_1228[6] = 0;
  auStack_1230 = (undefined  [8])0x400c32;
  strcat(local_1228,(char *)local_228);
  uVar3 = 0xffffffffffffffff;
  puVar5 = (undefined4 *)local_1228;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *(char *)puVar5;
    puVar5 = (undefined4 *)((long)puVar5 + (ulong)bVar6 * -2 + 1);
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  *(undefined8 *)(auStack_1230 + uVar3 + 7) = 0x65736162207c2027;
  *(undefined8 *)((long)local_1228 + uVar3 + 7) = 0x203e20642d203436;
  *(undefined8 *)((long)auStack_1211 + (uVar3 - 8)) = 0x697a2e6c6c657073;
  *(undefined2 *)((long)auStack_1211 + uVar3) = 0x70;
  auStack_1230 = (undefined  [8])0x400c9f;
  system(local_1228);
  auStack_1230 = (undefined  [8])0x400cb2;
  local_20 = fopen("spell.zip","rb");
  if (local_20 == (FILE *)0x0) {
    auStack_1230 = (undefined  [8])0x400cd5;
    printf("%s\n[-] There is no such file!\n\n",&DAT_0040127f);
                    /* WARNING: Subroutine does not return */
    auStack_1230 = (undefined  [8])0x400cdf;
    exit(-0x45);
  }
  auStack_1230 = (undefined  [8])0x400cfe;
  printf("%s\n[+] Spell has been added!\n%s",&DAT_00401202,&DAT_004011fa);
  auStack_1230 = (undefined  [8])0x400d09;
  close((int)local_20);
  return;
}
```

The first part of `spell_upload()` calls `read()` to take in input from the user. This input is checked as only containing `A-Z`, `a-z`, `0-9`, and/or the characters `.`, `\0`, `+`, and `=`; anything else throws an error and terminates the program.

Next, `spell_upload()` makes use of `strcat()` to build a system command: `echo (input) | base64 -d > spell.zip` and runs the command. This would suggest input needs to be base64 encoded to begin with.

Finally, `spell_upload()` verifies that `spell.zip` exists before returning.

## spell_save()

```c
void spell_save(void *param_1)

{
  undefined local_28 [32];
  
  memcpy(local_28,param_1,600);
  printf("%s\n[-] This spell is not quiet effective, thus it will not be saved!\n",&DAT_0040127f);
  return;
}
```

Spell save is particularly interesting, since will `memcpy()` more bytes than what the `local_28` buffer is sized to hold, allowing a buffer overflow to take place.

# Vulnerability

So a couple of things stood out to me immediately as interesting:

* There's a clear buffer overflow present in `spell_save()`. That function is only called from a successful execution of `spell_read()`, which passes the resulting data as an argument to the former. So if I want to overflow the buffer, I'll need to correctly format/execute `spell_read()`.
  * The unique bytes for the emojis need to be present to pass `spell_read()`.
  * I need to be mindful however that `NX` is enabled (per our checksec review at the top), which means I'll need to find some way to leak memory addresses from the binary to perform a `ret2libc` attack.
* Having us pass raw input to `spell_upload()` is interesting, but it doesn't look like a straightforward command injection attack is viable given the screening.

So my first goal was getting `spell_read()` setup.

I initially toyed around with something to the effect of:

```python
data = b'\xf0\x9f\x91\x93\xe2\x9a\xa1'
with open("spell.txt", "wb") as f:
    f.write(data)
    f.write(b'BBBBBBBBBBBBBBBBBBBBBBBBBBBBB') 

zip = zipfile.ZipFile("spell.zip", "w", zipfile.ZIP_DEFLATED)
zip.write("spell.txt")
zip.close()
```

and was going bonkers trying to figure out why the binary was throwing an error of `[-] There is no such file!`. Only upon looking at `clear()` did I realize what was happening:

```c
void clean(void)

{
  system("rm -rf spell.txt");
  system("rm -rf spell.zip");
  printf(&DAT_00401210,&DAT_00401202,&DAT_004011fa);
  return;
}
```

So I cannot just simply have an exploit file resident on the system to read in; in hindsight, that makes sense since we'll ultimately need to target a remote instance of this running process (and cannot control the local files on that system).

