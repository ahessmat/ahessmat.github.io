---
title: "Configuring an Anti-Cheat Dev Environment in Hyper-V"
published: true
date: 2025-06-24 00:00:00 +/-0000
categories: [general, notes]
tags: [anti-cheat, cheat]     # TAG names should always be lowercase
image:
    path: /assets/images/2025/ac-banner.png
---

## Starting Point

I've been interested in pursuing Anti-Cheat (AC) as a research area and - to that end - I've been wanting to setup a virtualized environment to facilitate my R&D efforts. However, getting this up-and-running isn't quite so clear cut. I've come up with a working solution and wanted to document this work somewhere for anyone else who might likewise be interested.

## Why virtualize?

While it's certainly possible (and - admittedly - faster) to get to any AC development on a baremetal asset, there are a few advantages to having a virtual machine (VM) to work with instead:

* A lot of AC development involves looking at and using existing cheats from untrusted sources. Not wanting to get my host machine infected, having the dev environment be isolated within a VM can help protect me from being overly-exposed to potentially malicious software.
* I'll eventually want to get to cross-examining kernel-level AC; a cursory search would suggest kernel development is more easily facilitated on a VM than on the host (alternatively, a second physical asset would be acceptable, but that incurs additional costs and downtime of the device).
* Certain AC detection efforts involve virtualization detection; there are cheats that exist in the sphere of manipulating hardware ID (HWID) bans and other memory read/write protections by way of VMs. Like the aforementioned kernel-level AC efforts earlier, this means eventually I would want to facilitate this.
* I feel a lot more liberal with tearing-down and rebuilding virtualized environments than I do my own host; VMs are more ephemeral to me.

Working in cybersecurity, I've worked quite a bit with virtual machines in the past but this would turn out to be an interesting learning experience.

## Early efforts and challenges

One of the first things I came to appreciate about AC development is that you generally need a good comprehension of game cheating itself. There are - fortunately - a lot of resources on this topic available. One of the first resources I had bumped up against was [a training module made available through Hack The Box](https://academy.hackthebox.com/course/preview/game-hacking-fundamentals); though far from the most authoritative source (and not free), access to the module does come with a PacMan clone, a safe version of `Cheat Engine`, and guided lessons on working with manipulating game process memory. I was already stepping through some companion training through [TCM Security on Malware Analysis](https://academy.tcm-sec.com/p/practical-malware-analysis-triage), so it wasn't a huge leap for me to leverage the FLARE VM from that to facilitate the Hack The Box lesson(s).

From that, I sought to expand my game hacking education and turned to the resources available at [Game Hacking Academy](https://gamehacking.academy/). It likewise starts off with working against a 2D game, though instead of a simple purpose-built one it teaches to a complete game to exploit: `The Battle for Westnoth`. For both of these 2D games, running the training through a Type-2 hypervisor like `Virtualbox` was more than sufficient. 

However, problems arise when trying to run 3D games (e.g. [Assault Cube](https://assault.cubers.net/), which is the de factor baseline training game to exploit for game-hacking instruction site [Guided Hacking](https://guidedhacking.com/)). By default, Virtualbox as a hypervisor emulates (vs directly using) your machine's GPU - this means the processing/rendering for games takes place on the machine's CPU instead; this results in a tremendous (and in my case: intolerable) performance hit that is noticeable to even a casual observer. Virtualbox *does* have some limited ["3D Acceleration" capabilities to it](https://docs.oracle.com/en/virtualization/virtualbox/6.0/user/guestadd-video.html), but it's pretty narrowly-scoped and didn't really create much of an impact on my test-case games.

This would mean I'd either have to do my AC dev on my host (which I didn't want to do for the aforementioned reasons) or explore alternatives.

## GPU Passthrough

Gaming in virtualized environments is not itself a novel idea. [Linux users in particular have explored this area at-length](https://www.reddit.com/r/VFIO/), since many PC games are designed for Windows OS only. Online searches frequently espoused reaching for KVM (a type-1 hypervisor) in order to facilitate "GPU Passthrough"; GPU passthrough allows for a VM to directly access the host's underlying hardware (namely, the GPU) thereby overcoming the aforementioned graphical limitations encountered with Virtualbox.

My problem is that KVM is tied to the Linux kernel and I use Windows as my daily driver operating system.

*"But why not change to Linux?"*

This was actually something I considered at one point; I'm not unfamiliar with Linux as an OS and am comfortable with a command-line, but I ultimately opted to remain as a Windows user because...

1. Habits are hard to break; I've grown up as a Windows user - it's been my daily driver for decades at this point. Moreover, I'd resolved some months ago that I'd get accustomed to Windows 11 with [the sunsetting of Windows 10](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro) and I wasn't especially keen to pivot into a Linux Distribution.
2. While I don't game *too* frequently, I do play videogames on occassion. As such, gaming through Linux can be a little bit of a hassle - much more so than on a Windows-based PC. Ironically, one of the big inhibitors is AC!

> I will note that I do like to run Linux as a VM for a variety of incidental tasks, especially for dev-related work and almost all things related to my profession in cybersecurity. It's just not ultimately what I wanted to run my personal machine on.
{: .prompt-info }

I likewise didn't bother reaching for dual-booting as an option; the idea of needing to power-down and reboot into a different OS to facilitate testing (or vis versa, in case something popped-up that required me to boot back into Windows) felt too cumbersome. What I wanted was a means of virtualizing my work!

### Hyper-V

It turns out the Microsoft has developed its own Type-1 Hypervisor: `Hyper-V`!

The more I looked into the solution, the more it looked like exactly what I wanted: I could run Windows 11 as my default machine without worry; I could trivially boot-up dev instances of Windows VMs as-needed to facilitate AC research; and Kali Linux provides a ready-made VHDX drive for Hyper-V, so my work that way wouldn't be affected. The one drawback appears to be that I cannot run both Hyper-V *and* Virtualbox at the same time; that's unfortunate since some of my work is definitely made easier through Virtualbox. However, I still have my own personal laptop which can manage the software (albeit at significantly reduced hardware specs), so I reckon I'll be fine.

Unlike KVM, `Hyper-V` allows for GPU *partitioning* vs. GPU *passthrough*. The former splits-up the GPU for use between machines (virtual or otherwise) while the latter dedicates the GPU. This nuance is only really important for optimizations at high-end performances, so for what I was looking to need it for the distinction didn't really matter.

## Setup

1. The first actions involved [enabling Hyper-V,](https://techcommunity.microsoft.com/blog/educatordeveloperblog/step-by-step-enabling-hyper-v-for-use-on-windows-11/3745905) which is disabled by default.
  - This step technically requires Windows 11 Pro (which I incidentally got to upgrade at no additional cost to), but purportedly [there's ways to enable this in the Home edition](https://gist.github.com/HimDek/6edde284203a620745fad3f762be603b) as well.
2. After completing the setup and restarting my computer, I used Hyper-V's "Quick Create" functionality to rapidly stand-up a Windows 11 VM.
  - I also got tired of (re)configuring a FLARE VM just to facilitate AC research; while it had some utilities that were certainly helpful, it was *way* too much (and too long to setup) for what I needed.
  - Since I'm working with [Microsoft Dev VM instances which expire every 90 days](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/), I figured I'd be setting up new instances periodically as-needed. To that end, I learned about [Chocolatey](https://community.chocolatey.org/), which serves as a Windows software package manager. I've since drafted [a quick choco powershell script](https://github.com/ahessmat/ac-setup) to run on the VM to get what I need quickly.
3. With the VM made, [I configured the host and VM to partition the GPU](https://www.youtube.com/watch?v=KDc8lbE2I6I). This proved to be pretty trivial in simply copy/pasting some files (the `C:\Windows\System32\DriverStore\FileRepository` directory and all of the `C:\Windows\System32\nv*` files for my NVIDIA GPU) from my Host machine to the VM and running the following powershell script in an Admin terminal on the host:

    ```powershell
    $vm = "<Name of Hyper-V VM>"
    if (Get-VMGpuPartitionAdapter -VMName $vm -ErrorAction SilentlyContinue){
        Remove-VMGpuPartitionAdapter -VMName $vm
    }
    Set-VM -GuestControlledCacheTypes $true -VMName $vm
    Set-VM -LowMemoryMappedIoSpace 1Gb -VMName $vm
    Set-VM -HighMemoryMAppedIoSpace 32Gb -VMName $vm
    Add-VMGpuPartitionAdapter -VMName $vm
    ```

4. The next thing we have to do is account for mouse volatility within the 3D games we play. While graphically the games should work fine, I found that mouse movement is interpreted wildly in-game ([like this guy experienced](https://youtu.be/Sx7-o9krbuc?t=836)). 
  - The reason for this is apparently is due to Hyper-V and the RDP protocol it uses for its "Enhanced Sessions". We want to use the "Enhanced Sessions" for all the added utility it provides (e.g. shared clipboard), but the exchange is that games then rely on absolute mouse movement inputs (vs. relative movement); this causes the seemingly erratic camera swings.
  - [The solution is actually pretty trivial](https://forum.level1techs.com/t/2-gamers-1-gpu-with-hyper-v-gpu-p-gpu-partitioning-finally-made-possible-with-hyperv/172234/198): another tool called [ParSec](https://dash.parsec.app/). Installing ParSec on both the VM and the Host machine allows for me to connect to the VM over ParSec's remote protocol, which is more stable than the RDP-based enhanced sessions.
5. After installing ParSec on both machines (and setting up a free ParSec account), the last thing I did was install the [VB-Audio Virtual Cable Driver](https://vb-audio.com/Cable/) on the VM for some quality-of-life improvements; doing this enables audio to be relayed over ParSec, so now I can hear gameplay too.
6. Now whenever I wanted to play a 3D game within the VM, I could boot up the Hyper-V VM and connect to it over ParSec.

## Closing thoughts

The above setup is a start, but it gets me to a point where I can now thoughtfully and methodically R&D some AC ideas in a controlled space that's trivial to tear-down and redeploy. There's still a lot I'd like to investigate further (e.g. getting Linux VMs besides Kali Linux running performantly), but for now these steps give me what I need to really sink my teeth into available materiel with confidence. Looking forward to really making some interesting AC discoveries!