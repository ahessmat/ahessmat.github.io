---
title: "Using n8n to Help Solve CTF problems"
published: false
date: 2025-11-07 00:00:00 +/-0000
categories: [research,notes]
tags: [resources, reverse engineering, binary exploitation, project, ai, agents]     # TAG names should always be lowercase
image:
    path: /assets/images/2025/ai1.png
---

The first thing we need to do is get n8n locally installed and running. I chose to locally-host n8n for several reasons:

1. It's free and - as someone who has never used n8n before - I was leery about shelling out cash for a service I was unfamiliar with.
2. I didn't want to host it within a VM because I wanted the workflows potentially accessible by other machines (and potentially services on my own Windows host).
3. I'm not really hampered by frequent travel (or the need for constant uptime), so I don't really need to rely on a VPS provider like n8n itself or Hostinger.

To get n8n installed, we first needed to get `wsl` (Windows Sysbsystem for Linux) installed on our Windows machine. Opening a `powershell` terminal and running `wsl --install` works, as does installing it through the `Microsoft Store`. Either way, you can then use the `wsl` command to install your choice of Linux Subsystem (and as of writing this post there are a fair number available):

| NAME | FRIENDLY NAME |
|:----:|:-----:|
|AlmaLinux-8                     |AlmaLinux OS 8|
|AlmaLinux-9                     |AlmaLinux OS 9|
|AlmaLinux-Kitten-10             |AlmaLinux OS Kitten 10|
|AlmaLinux-10                    |AlmaLinux OS 10|
|Debian                          |Debian GNU/Linux|
|FedoraLinux-43                  |Fedora Linux 43|
|FedoraLinux-42                  |Fedora Linux 42|
|SUSE-Linux-Enterprise-15-SP7    |SUSE Linux Enterprise 15 SP7|
|SUSE-Linux-Enterprise-16.0      |SUSE Linux Enterprise 16.0|
|Ubuntu                          |Ubuntu|
|Ubuntu-24.04                    |Ubuntu 24.04 LTS|
|archlinux                       |Arch Linux|
|kali-linux                      |Kali Linux Rolling|
|openSUSE-Tumbleweed             |openSUSE Tumbleweed|
|openSUSE-Leap-16.0              |openSUSE Leap 16.0|
|Ubuntu-20.04                    |Ubuntu 20.04 LTS|
|Ubuntu-22.04                    |Ubuntu 22.04 LTS|
|OracleLinux_7_9                 |Oracle Linux 7.9|
|OracleLinux_8_10                |Oracle Linux 8.10|
|OracleLinux_9_5                 |Oracle Linux 9.5|
|openSUSE-Leap-15.6              |openSUSE Leap 15.6|
|SUSE-Linux-Enterprise-15-SP6    |SUSE Linux Enterprise 15 SP6|

While reaching for `kali-linux` is tempting (I'm going to want to experiment with that later), I think I'll go with `Ubuntu` instead. Running `wsl --install -d Ubuntu` will have WSL fetch the distribution and get it setup; afterwards, you'll need to reboot the Windows host machine in order to use it.

![alt text](/assets/images/2025/wsl.png)

After ge