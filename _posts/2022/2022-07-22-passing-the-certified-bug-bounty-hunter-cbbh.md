---
title: Passing the Certified Bug Bounty Hunter (CBBH) Certification Exam
date: 2022-07-22 00:00:00 +/-0000
categories: [general,certification]
tags: [cbbh,hack the box, htb, certification, bug bounty, popular]     # TAG names should always be lowercase
image:
    path: /assets/images/cert-cbbh.png
---

Earlier this year, HacktheBox (HTB) announced its very first certification – making its initial steps into the world of vendor accreditations alongside other established programs like CompTIA, ISC2, and SANS GIAC.

<center>
<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Introducing the FIRST <a href="https://twitter.com/hashtag/HTBAcademy?src=hash&amp;ref_src=twsrc%5Etfw">#HTBAcademy</a> certification 🎉<a href="https://twitter.com/hashtag/Hackers?src=hash&amp;ref_src=twsrc%5Etfw">#Hackers</a>, meet our brand new Bug Bounty Hunter Certification aka CBBH! Ready to hunt some bounties? Complete the job-role path, take the exam, and GET CERTIFIED! 👉 <a href="https://t.co/01ZDXmXDIH">https://t.co/01ZDXmXDIH</a><a href="https://twitter.com/hashtag/HTB?src=hash&amp;ref_src=twsrc%5Etfw">#HTB</a> <a href="https://twitter.com/hashtag/BugBounty?src=hash&amp;ref_src=twsrc%5Etfw">#BugBounty</a> <a href="https://twitter.com/hashtag/Hacking?src=hash&amp;ref_src=twsrc%5Etfw">#Hacking</a> <a href="https://t.co/cxodV6bSde">pic.twitter.com/cxodV6bSde</a></p>&mdash; Hack The Box (@hackthebox_eu) <a href="https://twitter.com/hackthebox_eu/status/1508466610759155715?ref_src=twsrc%5Etfw">March 28, 2022</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
</center>

I’ve been handling quite a few Web Application Security Assessments (WASAs) lately, which generally consist of performing black-box testing of client applications for exploitable vulnerabilities. These activities mirror some of the offerings of modern bug bounty platforms such as HackerOne, BugCrowd, Synack, and others. As a result, my interest in [HTB’s Certified Bug Bounty Hunter (CBBH) certification](https://academy.hackthebox.com/preview/certifications/htb-certified-bug-bounty-hunter/) was piqued.

## CCBH Training Material: HTB Academy

The CBBH is tightly-linked with [HTB’s Academy service](https://academy.hackthebox.com/), a distinct training offering that complements its [better-known hacking labs](https://www.hackthebox.com/). In fact, before you can even sit for the exam you’re required to complete 22 academy modules covering a wide range of subjects, including (but not limited to):

* Javascript Deobfuscation
* SQL Injection Fundamentals
* File Upload Attacks
* Server-side Attacks
* Web Server & API Attacks
* Command Injections

If you haven’t indulged in HTB Academy, I’ll tell you that it’s very informative and seamless in its content delivery. Students are exposed to subjects at length; I found that even modules that covered fundamental areas that I well-understand had new or otherwise enlightening bits of knowledge to pick up on. You can connect with a VPN key to use your own machine’s tools or leverage the Academy’s in-browser “pwnbox” (a [Parrot Security Linux distribution](https://www.parrotsec.org/) with all of the tools necessary to accomplish the given module). Every module is capped off with a “Skills Assessment”, a virtualized instance of a vulnerable web app that is intended to be an unguided opportunity to exercise the skills/knowledge of the given module.

While in most instances I found the training fantastic, there were some aspects I didn’t care for. Most of the sections belonging to a module require performing some kind of hands-on exercise; the sections’ guided questions have the student step through a particular method in order to identify specific answers. By and large, this works. However, this does mean that if you don’t understand what is being asked of you (or you are required to perform some particular edge case to yield an answer), your progression through the academy can grind to a halt. I found that one section of the “Broken Authentication” module was a grinding exercise in timing in order to steal a user’s token; despite well-understanding the point that the section was trying to make, I had no other recourse than trying/re-trying my exploit code over-and-over. Fortunately, these misgivings are easy to get over given [the very helpful Discord channel](https://discord.gg/hackthebox) where you can work with your peers on figuring things out.

## CBBH: The Exam

HTB explicitly doesn’t permit anyone to disclose particular details of the exam (understandably). In fact, everyone who takes the exam is required to accept HTB’s terms of service (which covers these prohibitive non-disclosure requirements thoroughly). I will likewise observe and honor these constraints in this review; any information noted here is disclosed publicly by HackTheBox.

After completing the requisite modules, you can buy an exam voucher (valued at the time of writing at ~$210 USD). When you’re ready, you can take the exam on a machine of your choice, connecting to the exam environment via VPN (or their supplied Pwnbox).

Upon entering the exam, the student is presented with a letter of engagement which defines the engagement details, requirements, objectives, and scope. This engagement letter serves as an added layer of authenticity by HTB in an effort to foster professionalism in its students; the end product shouldn’t just be a certificate-holder, but a more holistic professional.

The exam - unlike certification exams offered by other vendors - does not directly test your knowledge retention through Q&A multiple-choice formatting. Instead, Hack The Box has endeavored to model the exam as a practical application environment, erecting model application(s) for the examinee to perform the entire bug bounty hunting process in realtime.

The exam environment will remain available for access to the student for (7) calendar days from the time of starting. You are encouraged in that time to take breaks, get sleep, and space out your testing efforts. The exam is not proctored (other than whatever logging HTB might be doing on their end through the VPN connection) and you are permitted to use any notes or resources (such as the internet), just as you would in a real bug bounty engagement. In order to pass the exam, you must earn a minimum number of points and submit a formal writeup of discovered vulnerabilities before the close of the 7th day. The instructions for how points are earned are explicitly spelled out for you in the exam. You can reasonably expect that the content provided by HTB Academy is representative of the exam environment, although that does not guarantee you will pass.

## CBBH vs. OSCP

Many people in the HTB Discord channel draw parallels from this exam to Offensive Security’s OSCP. Having passed both exams, I can say that there are certainly some aspects to this training/certification that will feel similar to the OSCP. Both cover web application attacks, both exams take over 24+ hrs to complete, and both require a formal written report accompanying student efforts. However unlike the OSCP, the CBBH:

* Leans more deeply into the area of web application blackbox testing, whereas the OSCP’s breadth includes post-exploitation attacks and Active Directory enumeration.
* Has a more integrated education model, embedding the exercises directly into the modules (unlike Offensive Security’s PWK, which pairs a PDF document with a VPN lab).
* Is more cost-effective.
* Is less stress-inducing; having 7 days (vs. the OSCP’s 24hr testing + 24hr reporting windows) to execute the exam provides greater flexibility of the student to get other things done and work the problems with a well-rested mind.
* [Is less impactful on one’s employability]({% post_url 2023/2023-11-08-what-certifications-should-you-get %}); HTB’s certification is new and niche to web applications in the greater cybersecurity job domain. Perhaps in time it will prove to be more recognized by industry professionals, but there is no denying that in the foreseeable future the OSCP does more for a penetration tester’s employability.

There are two other aspects of the exam that I think are really praise-worthy of the vendor:

* You get two attempts at the exam for the cost of a single voucher. Should you fail on your first attempt, you will have 14 days from the time that HTB formally notifies you of your failure to try the exam again at no additional cost.
* Should you fail your exam, you will receive written feedback on how you might improve. While this feedback isn’t so explicit as to spell out how to pass the exam, it is *very* generous. Closely reviewing your own notes alongside the exam feedback can be a major source of “aha!” moments that can make-or-break subsequent attempt(s). This feedback is only supplied if you submit your formal writeup however, hence why I strongly encourage all students to do so.

## Takeaways

I think that absolute newcomers to the field of offensive cybersecurity will find the CBBH more approachable than HTB’s other offerings (such as the standalone machines or subscription ProLabs). They may likewise find the training model to be more conducive to teaching rather than the PWK’s model of applied learning; I found things to be more transparent with peers willing to aid each other working through HTB’s Academy than in my experience with the PWK lab.

While understanding how to code isn’t a hard prerequisite of the CBBH, your time with it would be made much easier in understanding a basic scripting language (bash, python), PHP, Javascript, and SQL. The HTB Academy does a decent job of providing context explanations of what all its code snippets will do, but there is some presumption that you know how to read basic code in this manner. You won’t be delving into exploit development ([which the OSCP briefly touches on](https://steflan-security.com/complete-guide-to-stack-buffer-overflow-oscp/)), but you may find it useful to draft/modify small segments of code on-the-fly, as needed.

While I would say that CBBH is certainly easier than the OSCP, that doesn’t make the exam easy. I was challenged to think of creative approaches to problems, to innovate on top of taught approaches, and really become enmeshed in some complex techniques. It was a great learning opportunity and I highly recommend anyone looking to bolster their web app security skill set to consider it.

![My CBBH Cert](/assets/images/cert-cbbh.png)_My Issued Certification_