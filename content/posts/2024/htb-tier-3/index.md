---
title: "HTB Tier 3 Path Review"
draft: false
date: 2024-02-05
summary: "Late in 2023, Hack The Box announced new Senior Web Penetration Tester training path along their Academy platform which aligns to their Certified Web Exploitation Expert (CWEE) certification. The CWEE - released earlier in 2024 - is the first of their certifications which included **Tier 3** module content; up until now content aligned to their certifications (the CDSA, CBBH, and CPTS) all exclusively engaged **Tier 2** material."
tags: [resources]
aliases: 
  - /posts/htb-tier-3/
---

<style>
  /*This is code to make the dropdown menu a little more aesthetically pleasing*/
  @keyframes details-show {
  from {
    opacity:0;
    transform: var(--details-translate, translateY(-0.5em));
  }
}
details[open] > *:not(summary) {
  animation: details-show 150ms ease-in-out;
}

</style>

## Introduction

Late in 2023, Hack The Box announced new Senior Web Penetration Tester training path along their Academy platform which aligns to their Certified Web Exploitation Expert (CWEE) certification. The CWEE - released earlier in 2024 - is the first of their certifications which included **Tier 3** module content; up until now content aligned to their certifications (the CDSA, CBBH, and CPTS) all exclusively engaged **Tier 2** material.

<center>
<blockquote class="twitter-tweet"><p lang="en" dir="ltr">New level unlocked 🔓 <br>Introducing the Senior Web Penetration Tester job role path on <a href="https://twitter.com/hashtag/HTB?src=hash&amp;ref_src=twsrc%5Etfw">#HTB</a> Academy! 15 modules will walk you through identifying advanced and hard-to-find <a href="https://twitter.com/hashtag/web?src=hash&amp;ref_src=twsrc%5Etfw">#web</a> vulnerabilities to take your expertise to the next level.<br><br>⭐️ You can now access the path with the new… <a href="https://t.co/7n3HRE5PWR">pic.twitter.com/7n3HRE5PWR</a></p>&mdash; Hack The Box (@hackthebox_eu) <a href="https://twitter.com/hackthebox_eu/status/1735706734704886220?ref_src=twsrc%5Etfw">December 15, 2023</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
</center>

Implicitly, the release of the path was meant to suggest that this training would be more challenging and I was eager to see how. At-a-glance, the path is composed of the following modules:

* Injection Attacks
* Introduction to NoSQL Injection
* Attacking Authentication Mechanisms
* Advanced XSS and CSRF Exploitation
* HTTPs/TLS Attacks
* Abusing HTTP Misconfigurations
* HTTP Attacks
* Blind SQL Injection
* Intro to Whitebox Pentesting
* Modern Web Exploitation Techniques
* Introduction to Deserialization Attacks
* Whitebox Attacks
* Advanced SQL Injections
* Advanced Deserialization Attacks
* Parameter Logic Bugs

This blog post is a review and summary of the Tier 3 training path that aligns to the CWEE certification. It speaks to questions like "what do you learn?" and "what can I expect?". It is not a walkthrough of the material, nor does it speak to the answers for each of the modules' questions and their respective "Skills Assessments". In alignment with Hack The Box's terms of service, I encourage you to engage their Discord and Forums for aid in that regard. However, I do highlight fixes to administrative issues I encountered throughout, as I believe these are not deliberately built into the respective lesson objectives and do not otherwise detract from the learning experience. In addition to the brief summaries below, you can click on the dropdown menus to view my feedback on the individual modules' sections.

## Injection Attacks

This module is very quick to complete. Unlike the Tier 2 **Command Injections** module, which covers injection testing methodologies more broadly, **Injection Attacks** more narrowly focuses on three technologies and how they specifically can lead to vulnerabilities in an application. While this deepens your understanding of the attacks against them specifically, I think that this module is erroneously titled, focusing on XPath and LDAP Injections more particularly and bolting-on attacks on PDF-generators at the end.

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>

#### Introduction to Injection Attacks

This module kicks off with more narrowly framing the lesson to a particular set of technologies: XML Path Language (XPath), Lightweight Directory Access Protocol (LDAP), and PDF-generators. For folks more interested in command injection more broadly, the Academy offers a distinct `Command Injection` module. 

#### XPath Injection

The section is the longest in the module, describing a variety of ways that the XML language can lend itself to abuse. However, some of the methods feel relatively derivative: the **XPath - Authentication Bypass** was *very* similar to SQL injection (albeit with some minor syntactic differences) and  **XPath - Data Exfiltration** was likewise similar (albeit with a little LFI thrown in).

The **XPath -Advanced Data Exfiltration** and **XPath - Blind Exploitation** subsections were where the real learning value of the module resides. There is a lot of really interesting material to mull over and perform in the respective exercises that make them really worthwhile.

#### LDAP Injection

This section was likewise pretty straightforward to perform; I think the real value to me was having some handy references to LDAP syntax, which I often trip over and lose a lot of time on in formatting.

#### HTML Injection in PDF Generators

This section felt pretty niche to me; interesting to be sure, but niche all the same. The gist of it revolves around exploiting vulnerable PDF generation capabilities that may be present in web apps such that input is interpreted/executed as JavaScript code. The kinds of attacks you can perform are therefore likewise derivative to whatever you can maliciously perform with injected javascript (e.g. Server-Side XSS, SSRF, LFI, data exfiltration, etc.). I thought this was interesting, but wasn't really sure how applicable testing for this vulnerability might be outside of Hack The Box's gamified environments.
</details>
</div>

## Introduction to NoSQL Injection

I thought this module was pretty cool, being familiar to the idea of non-relational databases but without having extensively tested against them. To that end, this module was filled with some pretty neat content that was easy to follow along with but nuanced enough to appreciate the technical complexity. My only complaint here - which is fairly consistent with the Academy at-large - is that the tools they provide/suggest aren't always intuitive or helpful; however, there's plenty of open source alternatives available that I engaged which made this module altogether a more pleasant experience.

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### Introduction

This section describes some differences between relational databases (e.g. Oracle, MySQL, etc.) and non-relational databases, the latter of which are the module's focus. To help orient us, we're introduced to using **MongoDB** and the syntax for engaging it, which becomes important later for performing exploits. The only exercise for this section involves understanding how to efficiently query MongoDB, which can make the experience anywhere from simple to a little time-consuming, depending on on how well you take to the lessons.

#### Basic NoSQL Injection

For me, this section introduced something that was paradigm-shifting: altering web request parameters. In the past, these values have always been absolute. However, discovering that I could change something like `password=something` to `password[$ne]=something` for NoSQL testing was really interesting. The accompanying exercises can be followed-along almost word-for-word.

#### Blind Data Exfiltration

This section is very reminiscent of learning Blind SQL injection techniques more generally; the idea here is that you're relying on indirect indicators to tease out information piece-by-piece. The examples provided by the exercises can be performed either using the custom python scripts they provide (to help with automation) or via Burp Suite Intruder. The section also goes on to show how NoSQL injections can be paired with certain Javascript vulnerabilities for interesting effects.

#### Tools of the Trade

This section is brief, surveying a few tools that can be used including **wfuzz**, **NoSQLMap**, and an extension to Burp called **Burp-NoSQLiScanner**.

#### Defending Against NoSQL Injection

This section - like other similar sections offered throughout offensively-oriented modules - is strictly dedicated to defensive countermeasures to the aforementioned attacks. Unfortunately, it offers no exercises.
</details>
</div>

## Attacking Authentication Mechanisms

This module builds off of what is learned in the **Broken Authentication** module. However, where **Broken Authentication** focuses on basic attacks more generally (e.g. brute forcing, password inference, etc.), this module more narrowly examines technical vulnerabilities present in particular authentication mechanisms. Namely: JWT, OAuth, and SAML-supported SSO. I thought this module was pretty good, however the exercises didn't always help with solidfying comprehension.

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### JWT

If you've never encountered a JSON Web Token (JWT) before, then this is the section for you. It goes over what it is and the common misconfigurations/vulnerabilities that can stem from them. However, I think this section - with the exception of **Insecure KID Parameter Processing** - isn't Tier 3 content. What's covered isn't difficult to comprehend nor novel; unlike other modules, you're not really being presented anything new or in a way that isn't covered just as well/succintly elsewhere, which was a little disappointing. The exercises are straightforward and simple enough to complete.

#### OAuth

OAuth is a subject that always seems to trip people up, myself included. This is clear when half of the subsections are dedicated just to explaining OAuth's nuances before you arrive at a practical application exercise. Even still, I think that the exercises are presented in the wrong order; I would suggest users do the **Open Redirect** subsection *before* the **redirect_uri misconfiguration** - it's a simpler exercise and more effectually eases you into the practical application.

#### SAML

The SAML section was interesting to me. I had never used **SAML Raider** as a Burp extension before; consequentially, there was a fair amount of back-and-forth where I didn't understand what was happening and was encountering errors that I found to be frustrating. While the subsections like **Weak Public/Private Keys** do a great job of providing many screenshots to step-by-step you through the process, there were still times where I got hung-up on troubleshooting an issue. For example, I didn't realize I needed to navigate away from the SAML Raider pane and then return back again in Burp Repeater after configuring an updated cert for it to refresh properly. I made a note to seek out additional training concerning SAML in the future; I think the Academy does a good job of describing the vulnerability, but the exercises themselves didn't help solidify the knowledge - I felt very tool-bound by the section's end (i.e. if the tool fails, I wouldn't know what to do).
</details>
</div>

## Advanced XSS and CSRF Exploitation

This module was both one of the most rewarding along the path and the most frustrating. It's unique in providing some supporting architectural elements (i.e. an exploit & exfiltration server); these elements generally help with streamlining the learning experience - allowing users who don't possess more expensive licensed software like **Burp Suite Pro** access to the training. However, these learning aids come with some inconsistent application and hiccups which can be really frustrating. More than once I found myself battling the architecture vs. just engaging the problem; this is something I think is bound to happen when instruction isn't transparent about where/how victim users are artificially being simulated.

However, once you get past that the details and exercises that accompany the training are really great. There's a lot of practical application to be had all throughout the module, which affords some good opportunities to really sink your teeth into a kind of vulnerability that typically lacks nuance in its surface-level understanding; you go well beyond simply passing `<script>alert(1);</script>` into form fields.

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### Introduction to Advanced CSRF & XSS Exploitation

This module is unique in that it supplies you a number of supporting malicious architecture upfront: an exfiltration server and an exploit server. The exfiltration server is intended to log inbound GET requests, which you can make use of in extracting various data from the exercise targets (e.g. cookies, web page contents, etc.). The exploit server is a staging area for malicious payloads that you craft.

Throughout the module, you use these two resources extensively - forcibly navigating victims to your exploit server and (as situations call for) routing responses back to your exfiltration server for observation. This section of the module is geared towards walking you through using the resources more generally with some easy XSS exercises.

#### CSRF Exploitation

This section is pretty beefy, being composed of 5 subsections all about **CSRF** and **CORS**. It starts by recapping what Cross-Site Request Forgery (CSRF) is, then denotes a number of defenses used to protect against it including **CSRF Tokens**, **HTTP Origin/Referer Headers**, **Same-Origin Policy & CORS**, and **SameSite Cookies**; the rest of the section is dedicated to learning how you might subvert those controls. Most of the exercises are phenomenal, but there are a handful of situations that logistically made things tricky.

More generally, the module inconsistently applies when you should suspend your sense of disbelief about how the victim receives your malicious payload. Sometimes - like in the "Introduction to Advanced CSRF & XSS Exploitation" section - you actually need to find an XSS vulnerability within the app and plant your payload; under these circumstances, the exercise(s) have an automated script that artificially has the victim user navigate to the page and trigger the payload. Other times however, you are permitted (or obligated) to handwaive that step and forcefully supply your malicious payload by way of the **Deliver Payload** functionality within the exploit server. This inconsistent application was frustrating, because if something's not working, you're unsure whether its a problem with the payload, your comprehension of the problem, the delivery channel, etc. This section in particular was made very frustrating by this.

The second issue comes with troubleshooting payloads; the Academy recommends you test your payloads with you own browser (navigating to the exploit yourself and seeing how it behaves) to determine what problems may exist before pushing the payload to the victim user. However, modern browsers have a number of additional controls in place to mitigate XSS/CSRF. For example, Firefox (the default browser in a number of distributions used by HTB users, including Kali and Parrot) has a "Privacy & Security" setting which blocks cookies from being transmitted by XHR requests by default with the "Standard" setting (this is configured by default in the Pwnbox). This means ocassionally the exploits *as written* won't work on your browser, but *will work* against the victim user. This discrepancy was *enormously* frustrating for me - I wasted a considerable amount of time trying to figure out a payload that would run against my own machine when said non-functioning payloads would work perfectly well against the adversary. 

#### XSS Exploitation

This section is the longest in the module and the last before the Skills Assessment. Assuming you came to understand the troubles described in the previous section, this one is pretty straightforward with some really creative applications of XSS. For example, they show how XSS can be used to enumerate hidden pages/content, chained together with other vulnerabilities like LFI & Command Injection, and even lead to SQL injection and internal network mapping. The exercises are great and the provided example payloads I was grateful to add to my collection.
</details>
</div>

## HTTPs/TLS Attacks

Unlike a lot of other content/training offered by Hack The Box, this module felt quite "academic". A lot of the vulnerabilities, exploits, and tools you engage with in this module aren't directly performed; most of the time, you're reading about a particular vulnerability or observing its effects in a provided PCAP file. On occasion you're given an exercise that has you perform the attacks described, with the heavy lifting performed by just a couple of tools introduced: **padbuster** and **TLS-Breaker**. The module shies away from getting into the math and proofs that undergird the research in the cryptographic attacks, opting instead to keep discussions at a high-level in observing protocol exchanges. Because of this, I think the module's author(s) may have been hamstrung in what they could showcase. Overall however, the descriptions of what's transpiring are excellently laid out for the lay-person, with those few exercises that you do perform the attacks being excellent.

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### Introduction to HTTPs/TLs

This module starts pretty simple and can be completed quite quickly. You're introduced to the concept of certificates, certificate authorities, and using **OpenSSL** early on. From there, the training segways to describing different versions of the TLS protocol and using **Wireshark** to examine some small PCAP files for details about the handshake. Overall, this portion of the module should feel like a brief catch-up for those who have never been formally taught about these matters, but executing the tasks presented is trivial.

#### Padding Oracle Attacks

This portion of the module introduces some interesting tools such as **padbuster** and **TLS-Breaker**, but the exercises are likewise quick to step through in comparison to the rather academic content. The **POODLE & BEAST** exercise in particular is pretty trivial, since you're asked more generally to replicate the padding format on paper rather than perform anything practical. 

I was annoyed at the **Bleichenbacher & Drown** section; I got hung-up on tool setup and configuration, initially being stymied by getting **TLS-Breaker** setup (needing to alter the **pom.xml** file to point towards where the **javadoc** binary was on my machine). Then after that I was frustrated by this error message:

![](/assets/images/2024/bleichenbacher.PNG)

While the module section specifies you need Java to use **TLS-Breaker**, it's [only in the wiki](https://github.com/tls-attacker/TLS-Breaker/wiki/1.-TLS_Breaker-Configuration) that we learn you explicitly need JDK 11 (the above errors being thrown by my default JDK 17). Changing this fixed the errors.

There's still some challenges to work through after this however, but these stray into the deliberate efforts organized by Academy, so I will not go further into detail about troubleshooting them. Hack The Box must be aware of how frustrating these efforts are however, because they offer to give you the plaintext **premaster secret** if you were to click on the "Reveal the Answer" button. If you are paying for lab time (i.e. limited availability to the in-browser Pwnbox) you should absolutely do this; running the attack in full takes a *very* long time (the Academy hints at upwards of 30 minutes - it took me quite a bit longer than that) where you're ultimately sitting around doing nothing else while waiting for the value to arrive.

#### TLS Compression

This section is a breeze, having no testable questions about it.

#### Heartbleed

This section is straightforward, assuming you installed the **TLS-breaker** tool earlier in the "Padding Oracle Attacks" section. You just need to run the provided commands. However, you may need to run it several times before reading in the requisite area of memory (such is the nature of the vulnerability).

#### Further Attacks

This section opens with with examining **ARP spoofing** and **SSL Stripping**, which has a trivial question affiliated with it. You also examine some documented **Cryptographic Attacks**, but only at a surface-level. The section closes out with **Downgrade Attacks**, which force a victim to use insecure configurations of TLS; however, like the rest of this section, you don't really end up doing anything practical (vs. examining PCAP files of traffic *suggesting* a downgrade attack).

#### TLS Best Practices

This section just goes over assorted TLS configurations for various technologies like Apache and Nginx. It then closes out by introducing you to **testssl.sh**, a script for scanning/enumerating TLS vulnerabilities before having you run the tool in order to answer some of the questions.
</details>
</div>

## Abusing HTTP Misconfigurations

This was a great module along the **Senior Web Penetration Tester** path. It thoroughly covered **web cache poisoning**, **host header attacks**, and **session puzzling**, all of which were really interesting to read-up on and learn about. The section questions presented a lot of variation and hands-on work to better understand the vulnerabilities, but also doesn't shy away from providing thorough briefs on the underlying technologies that can be the source for these exploitable vulnerabilities. Overall, this was one of the more enjoyable/worthwhile modules of the path and is appropriate at Tier 3.

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### Introduction to HTTP Misconfigurations

This part of the module is just a high level preview of the content to come: Web Cache Poisoning, Host Header Attacks, and Session Puzzling. There are no associated exercises.

#### Web Cache Poisoning

This is a phenomenal section in the module, thoroughly covering details of the attack. **Advanced Cache Poisoning Techniques** had good exercises in particular; the exercises that were presented were very similar to the walkthrough material, but had just enough variation so as to force you to step through the discovery process from square 1. My one sticking point was during **Tools & Prevention**, where you're required to download and use the **Web-Cache-Vulnerability-Scanner (WCVS)**. At the time, my version of ParrotOS was tied with GLIBC version 2.31 (you can likewise discover your version by running the `ldd --version` command); unfortunately, the latest binary release of WCVS would throw errors as a result, calling for GLIBC_2.34 at least.

![](/assets/images/2024/wcvs1.PNG)

Fortunately, the Github repo provides a number of alternative ways to install/run the tool. I opted to install it using Go, which lead to learning some other things. First, installing WCVS with `go` requires version 1.21 or higher. I was running 1.19, so I needed an updated version (you can discover your own version by running the `go version` command). To do this, I downloaded the latest version of `go` at the time (1.22) from `golang.org/doc/install`, then followed to appropriate instructions to unpack and install the archive along `/usr/local/go`.

In order to add the `go` binary to my PATH variable, I then updated my `~/.zshrc` file with the following lines:

```bash
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

Finally, this let me install the latest version of WCVS with:

```bash
go install -v github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest
```

And then the tool could be run like so:

```bash
~/go/bin/Web-Cache-Vulnerability-Scanner -h
```

#### Host Header Attacks

This was another interesting section that I thought was pretty engaging. It shows a variety of ways where tampering with the `Host` HTTP header can lead to all sorts of vulnerabilities in an application. Improper/unsafe handling of the host header can lead to authentication bypasses, logic errors, and more. I got hung up on a handful of the exercises, but not because of a logistical issue (but for want of creativity on my part). All-in-all this was a well-written and thoughtfully assembled section.

#### Session Puzzling

This section is all about examining what might be done with session ID cookies. More generally, it examines potential logic errors that can arise if certain only certain facets of a user's session cookie is considered at different points of the logic flow. We might - for example - be able to affiliate a particular username to a session ID using one part of the application, then submit that cookie to directly access some other part of the application elsewhere without ever having to authenticate. Overall, this section feels a *little* strung-out, since it very much feels like it's (re)presenting the same vulnerability several different ways, but that's still pretty useful for comprehension.
</details>
</div>

## HTTP Attacks

After a small break in my training schedule, this was a great module to return back in with. Though named "HTTP Attacks", it really was focused on 2 different kinds of vulnerabilities: CRLF injection as well as **Content-Length** and/or **Transfer-Encoding** tampering. Despite having a third category ("HTTP/2 Downgrading"), in practice it really felt derivative of the Request Smuggling portion of the module, which exhaustively showed how tampering with the **Content-Length** and/or **Transfer-Encoding** headers could lead to all kinds of mischief. Despite that, the training was still very good and appropriate to the Tier it aligns with. The particularly challenging subsections included **HTTP Response Splitting** and **TE.CL**, both of which had exercises that very creatively innovated on the concepts their respective material introduced.

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### CRLF Injection

I'll admit, I thought that this section was pretty weak from the onset. The **Log Injection** subsection felt very derivative from the Log Poisoning training presented in the Tier 2 **File Inclusion** module and the enumeration strategies presented in the Tier 2 **Command Injection** module. However, the **HTTP Response Splitting** subsection was unexpectedly challenging and - I feel - a good example of how Hack The Box presents material in a fundamental way and then is able to build upon it in creative fashions in its questions/challenges; in the course of completing that particular subsection, I learned more about HTTP Response headers and using XHR than what I would have expected in just what the subsection suggests is needed. The section wraps up with **SMTP Header Injections** - the accompanying exercise can be completed by a close reading of the material, though the solution is not a literal copy/paste of what's presented.

#### HTTP Request Smuggling/Desync Attacks

This section was pretty challenging in the way that the section author(s) structured the exercises, but the content itself was pretty good. On its face, the material provides you several different ways of how subtle differences in layered technologies can desynchronize HTTP requests from responses. Specifically, it looks at how they interpret where the end of a given HTTP request is (creating confusion between headers like **Content-Length** and **Transfer-Encoding**, which both can specify how long a message is, but may not correctly be handled by RFC standards correctly for a given proxy/web server configuration). While the material was sufficient in its coverage, the challenge to the exercises came from what went unspoken (e.g. changing HTTP verbs and/or combining multiple different **TE.TE** techniques together).

#### HTTP/2 Downgrading

This section has some interesting content, but only 1 exercise (which is fairly straightforward to perform given the examples). The section primarily denotes a number of ways where differences in protocols between layered components can introduce vulnerabilities. The exercise specifically focuses on instances where an intermediary proxy receives requests in **HTTP/2**, but then passes along requests in **HTTP/1.1** (e.g. **H2.CL** vulnerability). This is a real shame, considering the variations they put forward in **Further H2 Vulnerabilities**; in the future, I would hope that additional exercises are introduced to reflect these other vulnerabilities as well. Alternatvely, it wouldn't surprise me to learn that some of the techniques described in the "Further H2 Vulnerabilities" are instead reserved for the CWEE exam.
</details>
</div>

## Blind SQL Injection

If anyone is familiar with boolean-based and/or time-based SQLi, then this module should be relatively trivial. While the module does introduce some neat python scripts that can be tailored for various encounters, I'd argue that functionally the material is just an alternative to using SQLmap to attain the same outcomes (albeit with much greater granularity of control and stripped down in its capabilities). There is also a brief introduction to working with **Microsoft SQL** (MSSQL), including some elements of leveraging privileged commands to achieve RCE. Overall however, this module didn't feel quite up to the level of Tier 3 training as some of the other modules along the **Senior Web Penetration Tester** path (and I'd contend this could reasonably be bumped down to a Tier 2 module). Overall, the module isn't lacking in the quality of its training or its exercises, but the material covered didn't feel sufficiently "advanced" enough as to warrant its price-point.

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### Introduction to MSSQL/SQL Server

This section is just a primer for the content to follow. It highlights different tools for interacting with MSSQL databases specifically, namely `SQLCMD` (Windows) and `MSSQLClient.py` (Linux). The section has a single exercise which engages the student's ability to perform nuanced MSSQL queries. This is a trivial section, especially if you're already familiar with MSSQL.

#### Boolean-based SQLi

If you've never been introduced to the topic of boolean-based SQLi, then there's some good learning to be had here. Otherwise, this section should feel pretty familiar and be executed pretty quickly. The exercises are relatively trivial to perform, especially since they provide some python scripting to automate retrieving the answers for you. For me, I really liked having the `Optimizing` subsection, which discussed ways for speeding up the query process (and introduces some little Computer Science algorithmic considerations in the process).

#### Time-based SQLi

I'll admit, I was really hesitant about going into this section; previous encounters with time-based SQLi have always been a drag, especially using SQLmap. They usually amount to some agonizing exercises of wait-and-see. Fortunately, this section was really nicely laid out and - with the deliberate absence of SQLmap - made quite quick. I think the longest subsection were the **Out-of-Band DNS** exercises, but that's only because I took some time to try and mess around with the multiple alternative options presented by the section as a kind of self-imposed "extra mile" set of exercises. Altogether, this is a pretty neatly crafted section.

#### MSSQL-specific Attacks

This module looks at some specific (mis)configurations that MSSQL can have that can be exploited to perform additional attacks on the server. Most of what's covered here I've seen in other trainings (e.g. ZeroPointSecurity's CRTO); that said, the **File Read** subsection introduced some functionality I hadn't been previously introduced to which enables appropriately-permissioned users to read arbitrary files from a system. That was really neat to learn!
</details>
</div>

## Intro to Whitebox Pentesting

I'll admit, when I first started this module I was prepared for it to be a cake walk; after all, you're provided all of the source code (which doesn't change at all until the Skills Assessment), it uses the same framework (**NodeJS**), and the codebase itself is pretty small and intuitive. However, I ended up finding that this module was my favorite of all the modules leading up to it, since its exercises are so permissively open-ended in their applied solutions. Each subsection talks about a different way the same app could be exploited, focusing not just on the exploit, but the process of analysis that could lend to you arriving at discovering said exploit (the latter of which is arguably more important in a whitebox assessment). For each exercise, you're using the same NodeJS code that you can host as a localized server to test against before launching your complete exploit against the HackTheBox-hosted version of the same code.

It felt really nice to exercise some creativity in how to go about engaging the problem, and it felt satisfying to apply lessons from other modules in iterating those approaches. For example, one of the problems the module grapples with is data extraction (suggesting either hijacking the response body, the error message body, or inferring the content via time-based blind attacks) - in the process of going about the module, I worked on applying a different method altogether: out-of-band messaging, encoding responses into outbound requests (which worked locally, but failed in the exercise due to dockerized connectivity constraints). Altogether, this module took longer than others and - in my opinion - was one of the most enjoyable.

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### Whitebox Pentesting Process

This section of the module does not have any exercises. However, as tempting as it might be to click through the material, I'd urge students to pause a minute and read through what's listed. A lot of what's described covers processes similar to what I've encountered professionally either as a penetration tester or in application security engineering. I feel like this portion of the module and others like it (e.g. **Documentation & Reporting**) are glazed over as they distract from the "fun" of technical exploitation.

#### Code Review

For me, this was an interesting section since my job involves a considerable amount of code review. I think there were some great points made, including highlighting some of the strengths/weaknesses of utilizing vs. over-relying on services like **Github Copilot**. There's also a cursory dip into running **Node.js** applications (although far from anything you'd need to be proficient). Since the instructions are rather sparse on installing it on Kali linux systems, [I'll include a nice link here that will take care of you](https://deb.nodesource.com/).

#### Local Testing

This was surprisingly challenging. While all of the exercises for the section provide either hints of "Reveal Answer" buttons, the challenge is less in arriving at the correct answers (which is trivial), but in arriving at the correct payloads to achieve those answers. There was a lot of frustrating elements to understanding why particular methods of execution worked and others did not. For example, I knew commands were running with `exec`, but couldn't see the output until I substituted it with `execSync` paired with the `toString()` method. By-and-large, if you're stuck in a subsection, look ahead at the next one and you'll generally arrive at the commands necessary to achieve the correct answers.

#### Proof of Concept (PoC)

This subsection was both fun and challenging, building off of the toy NodeJS app that was introduced at the start of the module. The progression here is about making more complex payloads/exploits, but the problems are quite open-ended, allowing you to concieve of your own approaches. I found that my biggest point of friction up until this moment was sorting out the quotes/double-quotes in my payload, so I ended up base64-encoding the entire thing, putting it within a b64-decoding wrapper, and passing that to the the exploit. Something to the effect of:

![](/assets/images/2024/whitebox1.png)

Overall, this was great!
</details>
</div>

## Modern Web Exploitation Techniques

From the onset, this looked like a really long module, with 3 sections containing 5-6 subsections each. In actuality, most of the module's section are pretty quick/trivial to step through (I got hung-up on only one subsection related to **WebSockets**). Altogether, this module felt pretty lackluster in comparison to some of the others HTB has put together at the Tier 3 level. The one truly novel attack that's showcased is **DNS rebinding**, but its unfortunate how little practical application exercises are designed around it. The **Second-Order Attacks** section content could have probably been rolled into other pre-existing Tier 2 modules that cover the respective XSS, LFI, and Command Injection attacks in greater detail. While I did learn some things from the module, it was ultimately a bit of a let-down considering its pricepoint. This module felt like a kind of dumping ground for sections that wouldn't otherwise fit anywhere else (with the notable exception of the **Second-Order Attacks**, which feels included only to give the section more material to work with).

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### DNS Rebinding

This section talks about how - in principal - an attacker in control of a DNS server can rapidly reconfigure which IPv4 address a given URL resolves to; this allows for some interesting bypasses when a victim application interacts with the malicious URL. For a really interesting/complex attack, it was disappointing to see only 2 exercises allocated to the section. Worse still, one of those excersises was just a rehash of SSRF (which has a whole other Tier 2 module dedicated to it: **Server-side Attacks**). Reading through some of the other subsections provides some insight as to how it would be challenging to support multiple exercises, but it's still a a bit of a let-down (especially if DNS rebinding were to later show up in the CWEE exam).

#### Second-Order Attacks

This section describes so-called "second-order attacks", which capitalize on manifesting exploits in latent ways; they are not standalone vulnerabilities, but rather describe ways that other vulnerabilities might manifest (e.g. malicious data input at point A might not be problematic until later at point B). As such, the section as a whole doesn't really introduce anything particularly novel that isn't covered in greater depth/detail in other Tier 2 modules (e.g. **Web Attacks**, **Command Injections**, etc.). Instead, it showcases ways how data input in different ways can come together in creative fashions. Altogether, I found this section disappointing, redundant, and at times felt more in-line with CTF-like conditions (vs. instructing to something more applicable); I think the real takeaway someone might learn from this section is the need to creatively apply/arrive at various vulnerabilities, but I'm dubious that the particular techniques shown are of much use outside of Hack The Box.

#### WebSocket Attacks

I thought this section presented some new and interesting information in talking about WebSocket connections, denoted by the `ws://` and `wss://` protocol schemes. The section is really a showcase of how to operatively work with newer protocols (including HTML5) and less about a new attack, couching the provided exercises in performing things like XSS and SQLi (but through WebSocket connections). I got hung-up on the **Exploiting XSS via WebSockets** exercise for a minute because - in the course of testing different payloads - the backend ended up enqueuing my XSS payloads; consequentially payloads that *would* have worked ended up not working at all (much to my confusion/frustration). The easy fix to this was to simply reset the machine, but I did lose a considerable amount of time troubleshooting this.

It was also interesting to note that - for reasons unknown to me - while SQLmap *did* work in some of the section's/module's exercises, it would not always return back the totality of results; while working through one problem with a partner, we learned that SQLmap failed to list *all* of the column names from a particular table (whereas I - going through the process manually - did find them). This was an interesting learning point in-the-moment, though I'm uncertain how much of it is related to **WebSockets** vs. being an exercise in trust-but-verify methodologies in tool usage/enumeration.
</details>
</div>

## Introduction to Deserialization Attacks

I really liked this section. It covers the premise of deserialization attacks in not 1 but 2 different implementations (`PHP` and `Python`) as well as including a more robust remediation section (vs. a tagged-on single subsection at the end of the module, which is the case for most offensively-oriented modules in the Academy). I wasn't keenly familiar with deserialization attacks from the onset, but I felt like the module was really well crafted and covered the highlights of the vulnerability class quite well. While there were many exercises throughout the module, their were a handful of topics that I felt deliberately did not include an exercise (e.g. `JSONpickle`) which I presumed were reserved for either the exam. The path does feature a follow-up `Advanced Deserialization Attacks` module that's meant to be covered after this one.

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### Exploiting PHP Deserialization

This section was pretty straightforward. Since values from deserialized data get passed to various other functions in code, this section focused on showing how malicious values in that deserialized data can flow into PHP code to do harm. Some of the vulnerabilities are demonstrated as manipulated logic (i.e. `Object Injection`) others as malicious code injection (being passed to functions like `shell_exec()` for RCE or `mysqli_query()` for SQLi). The section also looks at deserialization through PHAR archives (very neat, though somewhat niche) and some tools to help automate the malicious serialization process. The section closes out by highlighting an interesting tool - `phpggc` - which can automate the process of crafting malicious serialized PHP payloads.

#### Exploiting Python Deserialization

This section parallels the previous one, but this time looking at the `pickle` library more narrowly.

#### Defending against Deserialization Attacks

This section is brief (containing only 2 subsections), with only one exercise that you can trivially perform without needing to download the supplied source code (or really go through the motions described). I think that this section would benefit from a better set of exercises, because being able to effectively remediate these issues is pretty important in the professional space.
</details>
</div>

## Whitebox Attacks

This was an extraordinary section that I felt lived up to its Tier in difficulty and value. The module looks at `prototype pollution`, `timing attacks & race conditions`, and `type juggling` vulnerabilities, with plenty of exercises devoted to each. I found it took me quite a bit of time to ingest/learn this module's content; there were a number of subsections that I spent several hours on working through. The "Whitebox" portion of this module is subtle; it's easy to more narrowly focus on the vulnerabilities and less on the practice of performing a source-code assessment. But I urge students engaging this module to slow down and actually read through the code, if only to develop a good habit. 

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### Prototype Pollution

This section was was great. It talked about some really interesting mechanisms for attacking a web application by way of JavaScript Objects and - more specifically - prototypes. There are three exercises to the section, each engaging the content in a new and interesting way. I found the exercises to be a little frustrating at parts; for someone entirely new to this kind of vulnerability, there's enough information present in the section to conceptually grasp at what's being talked about but just enough omitted that you will likely have to consult some outside material to supplement it. One of my favorite tool-takeaways that was introduced was BurpSuite's **DOM Invader**.

#### Timing Attacks & Race Conditions

This section was well written. It begins with orienting the student more generally on race conditions that they might recognize from other CTF-like challenges at the OS-level, then demonstrates how such Time-of-Check, Time-of-Use (`TOCTOU`) vulnerabilities might emerge within web applications. Along the way, students are provided some example python scripting to tool about with, as well as a `BurpSuite` extension (`Turbo Intruder`).

#### Type Juggling

Like the other sections before it, this was a really well-developed section within the module. `Type Juggling` vulnerabilities arise when loose comparisons are made (and data type values are assumed - i.e. `0 == null`); this can lead to some interesting bypasses and other issues. While couching the lessons in PHP, efforts are made throughout the module to highlight syntactic differences that exist in other languages as well. One of the really valuable resources supplied is a table of equivalent values interpreted by PHP; this was really useful for a number of the exercises.
</details>
</div>

## Advanced SQL Injections

This was a really good, but really frustrating section. Like many other sections in this training path, the emphasis for this module was on Whitebox code analysis; the SQL injection was merely a vehicle for engaging such analysis, introducing some nuances unique to PostgreSQL (vs. MSSQL, MySQL, or NoSQL injection - covered in their corresponding modules, respectively). While the training was good, I found that there were certain logistical issues that impeded the training - [including one instance where the source code was incorrect in a really important way](https://discord.com/channels/473760315293696010/1236757191676002384/1236757191676002384), ambiguous instructions for setting up dynamic analysis, and a frustrating lack of support in configuring our test environments for using downgraded versions of PostgreSQL; all of these issues felt less deliberate in their training value and more like oversights that could be readily fixed. If you move past those issues however, you'll find a module that is chock-full of engaging content and worthwhile lessons on the subject matter, including some useful python scripts to add to your toolbox.

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Module Details</summary>
#### Identifying Deserialization Vulnerabilities

This section was a little heavy for me, having not worked extensively with .NET applications very much. Consequentially, there was a lot of tangents and documentation that were pulled up to get oriented more generally. The module provides a minimal job of orienting you as a student to the tech stack, so if you're like me you might do a lot of pausing through this subsection to figure out architecturally what's happening.

Moving past that, this section introduces working with Jet Brains dotPeek and/or ILSpy for decompiling .NET applications from their intermediate MSIL format. Initially, I was pretty retiscent about standing-up a dedicated Windows 10 VM just to facilitate the module; as such I reached for a clone of ILSpy for Linux that I could run on Kali: `https://github.com/icsharpcode/AvaloniaILSpy`. In time I found however that standing up such a VM was the most practical for me (vs. using the supplied one given at the **Decompiling .NET Applications** subsection), given how slowly I progressed through the module overall; this let me walk away and return to the training hours (or days) at-a-time without losing progress such a configuration also helped facilitate troubleshooting malicious payloads (i.e. if a payload worked on a defaultly-configured Windows 10 VM out-of-the-box, I figured it would reasonably work in most cases on HTB).

Most of the exercises are pretty trivial to perform, with the one exception being what's found in **Debugging .NET Applications**, which requires *considerable* setup in order to facilitate. That said, the exercise is pretty well spelled-out step-by-step in the subsection. So while it's complicated and nuanced, it's relatively straightforward.

#### Exploiting Deserialization Vulnerabilities



This section was where having a dedicated Windows 10 VM setup on an internal network with my Kali VM really paid off. The first exercise presented in
</details>
</div>

## Advanced Deserialization Attacks
