---
title: HTB Tier 3 Path Review
published: false
date: 2025-07-21 00:00:00 +/-0000
categories: [general,notes]
tags: [resources]     # TAG names should always be lowercase
image:
    path: /assets/images/appsec.jpg
---

I'm interested in becoming more proficient in the security of AI and - more narrowly - LLM models. I've been pretty happy with some of HTB's options in the past, so I thought to evaluate its AI training offerings.

## Fundamentals of AI

https://academy.hackthebox.com/course/preview/fundamentals-of-ai

> Module at-a-glance:
> 
> * 6 chapters
>   * Introduction of Machine Learning
>   * Supervised Learning Algorithms
>   * Unsupervised Learning Algorithms
>   * Reinforcement Learning Algorithms
>   * Introduction to Deep Learning
>   * Introduction to Generative AI
> * 23 pages
> * (1) Skill Assessment
{: .prompt-info }

Broadness of AI, ML as a subset. That within ML there's (un)supervised learning, reinforcement learning. 

Offers a boilerplate on Mathematical notation



I've been interested in some applied research lately, particularly in the spaces of machine learning as it relates to cybersecurity. While I have a couple of irons in the fire at the moment so-to-speak, I wanted to callout something neat I've been toying with. In this post, we're going to look at building out a CTF agent!

Let's start with some of the intuition behind some of the decisions that follow:

While I eventually want to tie-in larger, more powerful models to be behind the agents, for learning and prototyping I wanted to start with something more localized. To that end, I pretty quickly zeroed-in on [Ollama](https://ollama.com/). Ollama is a really easy way to quickly spin-up local large language models (LLMs) - not unlike chatGPT - for use on your own hardware.

As an agent purpose-built for security-related tasks (namely: capture-the-flag challenges), I'm anticipating having the agent backdropped against a [virtualized instance of Kali Linux](https://www.kali.org/get-kali/#kali-platforms). Kali Linux comes with a lot of tools out-of-the-box to work with for many of the anticipated scenarios, which makes sense; I want to minimize the need for an agent to have to search for and download a tool that doesn't already exist on the machine. Additional controls (e.g. dockerized containers) are probably going to be advisable, but we'll cross that bridge when we get there.

Right out of the gate, there were a couple of challenges I ran into.

First, I needed to upgrade my hardware. I was already running into issues with my decade-old GPU being too deprecated to run [the latest version of PyTorch locally](https://pytorch.org/get-started/locally/), which was impeding some of the NVIDIA workshops I was participating in as part of a Georgia Tech seminar this semester. Looking around, the most cost-efficient card to support what I wanted to do without being exorbitantly expensive was the [NVIDIA RTX 3090](https://www.nvidia.com/en-us/geforce/graphics-cards/30-series/rtx-3090-3090ti/); at the time of purchase, Amazon was pricing the card between $900-$1400 - but I was lucky to find a used one for $700. For context, NVIDIA RTX 4090 and 5090 GPUs are pricing around $2300-$2500.

Why does a GPU matter? In brief, Graphics Processing Units (GPUs) were originally designed to accelerate computer graphics in being purpose-built for the parallelized math operations necessary to do so. This architecture also turned out to be excellent for the many vectorized matrix operations behind LLMs; GPUs have Video Random-Access Memory (VRAM), which serves as a type of dedicated memory for the GPU to quickly access/process data. With sufficient enough VRAM, entire LLM models can be held in this GPU memory - greatly accelerating model performance. Because I anticipate the agent to be making many queries and have a large context window, any Ollama model I run locally will need quite a bit of VRAM.

My next problem was in working with a VM. [In a post earlier this year](https://bytebreach.com/posts/hyperv-ac-setup/#gpu-passthrough), I dealt with first-hand the many problems of trying to setup GPU passthrough using a Windows base environment. For that particular setup, Hyper-V proved to work well. This time, I'm working within Virtualbox (because it's what I already use to help teach binary exploitation). VMs within Virtualbox don't have direct access to the hardware GPU (though they can emulate it through 3D acceleration), so setting up the model within the VM isn't tenable. The solution? I won't serve the Ollama LLM on the VM - I'll serve it on the host instead. Ollama can be configured as a server with a listening port that we can programmatically interact with from the VM.

(INSERT GRAPHIC SHOWING COMPUTER, OLLAMA, KALI LINUX VM ARCHITECTURE)

Things are still pretty barebones right now. First, we should import a model for our agent to reference. There's a wide selection to survey/consider, but we'll start with something basic like `deepseek-r1:8b`. To that end, we'll `pull` the model onto the local host after installing Ollama:

```powershell
ollama pull deepseek-r1:8b
```

Then in order to implement the above, we need to configure Ollama on the Windows host to listen for traffic from our Kali Linux VM:

```powershell
set OLLAMA_HOST=0.0.0.0
ollama serve
```

Then from the VM we can test connectivity by issuing a `cURL` command like so:

```bash
curl http://192.168.1.11:11434/api/tags
```

> Reference note: The IP address above should be replaced with the network IPv4 address of the host machine that's serving up the Ollama model. By default, Ollama models serve up a listening port along port number 11434. By making a call to `/api/tags`, we're anticipating a list of all the loclally available models.
{: .prompt-info }

With this, we've configured a basic setup. 


in this particular instance, having a GPU with a sufficiently sized VRAM capacity allows for entire models to be held in GPU memory, 

(and thus being valued by video game enthusiasts for beautiful imagery and )

> **Why does a GPU matter?** In brief, Graphics Processing Units (GPUs) were o

As someone who sports Windows OS as their Host OS, this 

To start: while I eventually will want to tie-in larger, more powerful models as agents, for learning and prototyping I wanted to start with something more localized. To that end, I turned to [Ollama](https://ollama.com/). Ollama is a really easy way to quickly spin-up local large language models (LLMs) - not unlike chatGPT - for use on your own hardware. 

I recently upgraded my decade-old GPU for an [NVIDIA RTX 3090](https://www.nvidia.com/en-us/geforce/graphics-cards/30-series/rtx-3090-3090ti/) (not the most performant, but pretty good for the pricepoint).

Now - ultimately - I want this agent to interact with tools available on a [virtualized instance of Kali Linux](https://www.kali.org/get-kali/#kali-platforms); with my host machine being Windows OS, this brings some complications:

