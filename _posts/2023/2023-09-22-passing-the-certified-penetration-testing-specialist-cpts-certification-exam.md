---
title: Passing the Certified Penetration Testing Specialist (CPTS) Certification Exam
date: 2023-09-22 00:00:00 +/-0000
categories: [general]
tags: [cpts,hack the box, htb, certification, pentest, popular]     # TAG names should always be lowercase
image:
    path: /assets/images/cert-cpts.png
---

About one year ago HackTheBox (HTB) announced its second certification available to the public: the Certified Penetration Testing Specialist (CPTS).

This certification follows their earlier [Certified Bug Bounty Hunter (CBBH) cert](https://bytebreach.com/passing-the-certified-bug-bounty-hunter-cbbh/) released in March of 2022, but extends lessons on the cyber killchain towards compromising a network in its entirety.

<center>
<blockquote class="twitter-tweet"><p lang="en" dir="ltr">📣 Attention everyone: a new era of <a href="https://twitter.com/hashtag/pentesting?src=hash&amp;ref_src=twsrc%5Etfw">#pentesting</a> certifications has arrived! We are proudly announcing a new certification: ready to turn <a href="https://twitter.com/hashtag/hackers?src=hash&amp;ref_src=twsrc%5Etfw">#hackers</a> into <a href="https://twitter.com/hashtag/pentesters?src=hash&amp;ref_src=twsrc%5Etfw">#pentesters</a>! <br>⚡ Complete the Penetration Tester path on HTB Academy, take the exam, and get certified: <a href="https://t.co/0wcdPNYn4y">https://t.co/0wcdPNYn4y</a> <a href="https://t.co/Xz17xC4KMG">pic.twitter.com/Xz17xC4KMG</a></p>&mdash; Hack The Box (@hackthebox_eu) <a href="https://twitter.com/hackthebox_eu/status/1574422266209005569?ref_src=twsrc%5Etfw">September 26, 2022</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
</center>

I was really impressed with HackTheBox’s last certification – the Certified Bug Bounty Hunter (CBBH). The accompanying training package was some of the most impressive and comprehensive guided-learning I’d encountered for web apps; so when HTB announced a second certification, I was eager to see what it was all about.

## CPTS Training Material: HTB Academy

The CPTS is tightly-coupled with [HTB’s Academy Service](https://academy.hackthebox.com/), a distinct training offering that complements its [better-known hacking labs](https://www.hackthebox.com/). Like the CBBH before it, you must complete all 28 of the accompanying modules before you can attempt the exam. These modules cover an array of subject-matter including (but not limited to):

* Footprinting
* Password Attacks
* Pivoting, Tunneling, and Port Forwarding
* Active Directory Enumeration & Attacks
* Privilege Escalation (Windows and Linux)

HTB Academy continues to be a seamless training platform, integrating its segmented training modules with tailored virtualized “victim” environments. This lets students immediately put into practice what they learn, cementing concepts by way of practical application. You can connect with a provided VPN key to use you own machine’s tools or leverage the Academy’s in-browser “pwnbox” (a [Parrot Security Linux distribution](https://www.parrotsec.org/) with all the tools necessary to accomplish the given module). Each module is capped off with a “Skills Assessment”, a virtualized instance of a vulnerable machine, web application, or network that serves as an unguided test of the skills/knowledge presented.

The 28 modules that make-up the so-called “Penetration Tester” job path can take a while to get through, even if you’re familiar with the content. If the material is totally new to you, it’d likely take you several months to both learn and ingest all of the modules’ contents. Fortunately, there is some overlap between the “Bug Bounty Hunter” job path (which aligns to the CBBH) and the “Penetration Tester” job path. Ergo, if you already were pursuing the CBBH first (which I’d generally recommend), you’d save almost half the time. A total of 11 modules are shared between them:

* Information Gathering – Web Edition
* Attacking Web Application with Ffuf
* Cross-Site Scripting (XSS)
* Using Web Proxies
* SQL Injection Fundamentals
* SQLMap Essentials
* Command Injections
* File Upload Attacks
* Login Brute Forcing
* Web Attacks
* File Inclusion

If you complete the modules once pursuing one certification, you don’t then have to repeat them again when pursuing the other. However, I would strongly advise you to do so (or at least re-read the material) in order to refresh yourself on the particulars before heading into the exam.

Most of the modules provide an accompanying “Cheat sheet” (markdown formatted) which can be downloaded and readily integrated into your own personal playbook. However, you’d do well to expand upon the cheat sheets, as they aren’t inclusive of all the nuances, commands, and options covered in the module’s sections (and lack the context of your learned experiences from the practical application exercises). When I stepped through the material, I downloaded the cheat sheet upfront and made additional annotations (complete with snapshots) to it as I worked my way through the corresponding module.

Most of the modules that were a part of the “Penetration Tester” path were phenomenal, but there were definitely parts where I got hung-up. Fortunately, HTB provides a number of services to help supplement your education, including [1-on-1 tutoring](https://www.hackthebox.com/blog/discord-lab-tutoring), [forums](https://forum.hackthebox.com/), and a very lively [Discord](https://discord.com/invite/hackthebox).

## CPTS: The Exam

HTB explicitly doesn’t permit anyone to disclose particular details of the exam (understandably). In fact, everyone who takes the exam is required to accept HTB’s terms of service (which covers these prohibitive non-disclosure requirements thoroughly). I will likewise observe and honor these constraints in this review; any information noted here is disclosed publicly by HackTheBox.

After completing the requisite modules, you can buy an exam voucher (valued at the time of writing at ~$210 USD). When you’re ready, you can take the exam on a machine of your choice, connecting to the exam environment via VPN (or their supplied Pwnbox).

Upon entering the exam, the student is presented with a letter of engagement which defines the engagement details, requirements, objectives, and scope. This engagement letter serves as an added layer of authenticity by HTB in an effort to foster professionalism in its students; the end product shouldn’t just be a certificate-holder, but a more holistic professional.

The exam environment will remain available for access to the student for (10) calendar days from the time of starting (vs. 7 days for the CBBH). You are encouraged in that time to take breaks, get sleep, and space out your testing efforts. The exam is not proctored (other than whatever logging HTB might be doing on their end through the VPN connection) and you are permitted to use any notes or resources (such as the internet), just as you would in a real penetration testing engagement. In order to pass the exam, you must earn capture a specified number of “flags” scattered through the exam environment and submit a formal writeup of discovered vulnerabilities before the close of the 10th day.

### Exam Experiences

You can reasonably expect that the content provided by HTB Academy is representative of the exam environment, although that does not guarantee you will pass. Below were some abstract experiences I had:

* There were occasions in the exam where I could clearly (and correctly) tell that there was a mechanism, technology, or piece of information that I was meant to use eventually in the test. The problem I had was thinking these details always immediately mattered. This would lead to fixation and becoming blind to other potential vulnerabilities, misconfigurations, and opportunities to actually progress forward.
* The inverse of the above was also true: on at least one occasion I got hung up trying to work a problem because I hadn’t paid attention to seemingly innocuous details encountered earlier. Examining my underlying assumptions about what I believed to be true often lead to “Aha!” moments of progress.
* It can be startling at times just how far you feel you’ve gone without encountering a flag, especially early on in the exam. There were a number of times where I felt that surely the next step would lead to a user/root/system compromise, only to discover another layer of nuance to sort through. This can feel disheartening at times, but is balanced by having other moments of the exam fly by.
* Undercutting everything is the knowledge that HTB has deliberately configured the exam environment to be vulnerable with a particular attack chain in mind. Everything is likewise couched in the corresponding HTB Academy modules training. Ergo, the bounds of what you are expected to do within the exam is generally less complicated than what your imagination might lead you to believe.
* As an extension of the above, when the next step in your attack chain isn’t intuitive it’s often helpful to go back through and run through the modules’ exercises. Oftentimes, my biggest roadblocks were a consequence of exhausting my own ideas; turning to the Academy’s lesson materials almost always turned up added possible ways forward.

# CPTS vs. CBBH

While both of HTB’s certifications focus on offensive techniques, the accompanying study materials and exam structures differ in important ways.

The CBBH exclusively is concerned with web application vulnerabilities. The accompanying training focuses on getting up to remote code execution (RCE) on the underlying host and no further. To that end, it exhaustively details a myriad of techniques for compromising web applications in ways the CPTS training does not – introducing classes of vulnerabilities that a CPTS student wouldn’t be formally taught. In exchange for shallower coverage on web apps, the CPTS curricula extends well beyond the initial breach; you delve into the domains of privilege escalation, active directory attacks, etc. Where a CBBH student gets to RCE and asks, “what now?” a CPTS student learns how to carry-on the attack chain towards full dominance of a client’s network(s).

A useful analogy might be the difference between driving through multiple cities (CPTS) vs. living in one (CBBH). In the first case, the driver sees elements of the towns they pass through – a breadth of experiences. In the latter instance, a resident is intimately familiar with how to navigate their literal area of expertise – a depth of experience. If you’re weighing which one to work through first, I’d probably advocate for the CBBH, which feeds more neatly into the studies for CPTS (not so vice versa).

The exams are likewise structured differently. I can’t go into particulars, but in the CBBH if you ever feel stuck there are multiple independent lines of effort you can switch between to try and drive your progress forward towards passing; students who pass the CBBH exam may do so through different combinations of approaches. By contrast, in the CPTS if you get stuck your only recourse is to figure out how to unstick yourself; the exam has a very linear structure about it with the expected flags unambiguously suggesting the direction you’re meant to go about it.

## CPTS vs. OSCP

There’s some direct comparisons that could be made between the CPTS and the long-time de facto certification in the offensive space: the [OSCP](https://www.offensive-security.com/pwk-oscp/). Having passed both exams, I can say that there is definite overlap in the content each covers – especially since [Offensive Security overhauled their exam](https://www.offsec.com/offsec/oscp-exam-structure/). The unique features about the CPTS I’ve highlighted below:

* The CPTS has a more seamless/integrated education model; the trainings are more neatly interwoven with the practical application exercises, enabling accessibility and promoting better retention.
* The learning environment offered by HTB Academy is structured around learning (whereas Offensive Security’s is geared more towards testing). Studying for the OSCP was a frustratingly lonesome experience, especially when I was stuck in learning a particular concept/technology; your peers often only can provide cryptic clues that make sense retroactively, there’s no centralized authority to submit questions to, and the “Try Harder” mentality puts a general chilling effect on community engagement. By contrast, you’re more than welcome to be transparent with what you do and don’t know all throughout your learning journey with HTB Academy (shy of exam details or total walkthroughs) through their many different channels of communication.
* The cost of the CPTS + its learning materials is a fraction of what the OSCP’s are. All the more so when you realize that a single purchased exam voucher for the CPTS is good for two (2) exam attempts.
The test window and proctoring policies are significantly relaxed for HTB’s certifications in comparison to the OSCP. Having a multi-day time window makes things significantly less stressful (and – frankly speaking – more representative of professional engagements) than what the OSCP requires.
* You receive written feedback on your exam performance if you fail; these comments can help serve as suggestions as to how you might improve on subsequent attempts (although their efficacy/helpfulness I found to be less impactful than when I engaged the CBBH). No such commentary is given for the OSCP.

Unfortunately, the CPTS just isn’t as impactful to your employability. Moreover, there doesn’t appear to be nearly that much community interest in it compared to some of HTB’s other offerings (i.e. their standalone machines or ProLabs environments); in the year since its release, less than 500 people have completed the Academy pathway modules and just over 100 have completed the exam (an argument could be made that it’s because of the exam’s difficulty, but that's just speculation; folks may elect not to take the exam for the cost, they perceive less ROI in the cert vs. the Academy, etc.). [I haven’t seen employers asking for the CPTS on any job listings]({% post_url 2023/2023-11-08-what-certifications-should-you-get %}). I also haven’t seen HTB doing much in the way of promoting their own certifications in competition with comparable established certification vendors (e.g. SANS, EC-Council, eLearnSecurity, and of course Offensive Security).

However, I think the real value of the CPTS is in the accompanying HTB Academy training. It’s fantastic. It’s updated frequently, well-curated, and provides context and background to technologies/techniques succinctly with actionable examples. By creating a pathway that caters to the CPTS, students are encouraged to engage the platform’s numerous lessons which are both informative and fun. [Students enrolled in university likewise have a discounted price tier](https://www.hackthebox.com/blog/htb-academy-cpe-credits-and-student-subscription), which makes nearly all of the Academy’s content accessible (note: all of the necessary modules for both the CPTS and CBBH are available with the student subscription). But all of this value rests with HTB Academy, independently of the CPTS. This keeps me wondering what is the added value that the CPTS brings to test-takers (vs. using the Academy to springboard their studies to more impactful certifications, like the OSCP or SANS’ GPEN).

## Closing Thoughts

I think that the CPTS is an appropriate avenue for onboarding folks new to offensively-geared cybersecurity to the domain. Folks new to cybersecurity (or tech more generally) will probably struggle, but HTB’s supporting infrastructure and Academy modules are great for providing guidance. I’d probably put the difficult of the exam as being harder than eLearnSecurity’s eJPT and EC-Council’s CEH, but easier than Offensive Security’s OSCP.

You don’t necessarily need to understand how to write code before you begin the HTB Academy path for the CPTS, but it sure would help to know how to read object-oriented scripting languages like Python, Powershell, and Bash. There are some select moments within the Academy pathway where those unfamiliar with low-level syntax can feel overwhelmed (the “Attacking Thick Client Applications” portion of the “Attacking Common Applications” module was particularly dense, as I recall), but nothing is so far out of the way that a Google search and a couple questions can’t solve it.

The journey towards attaining my CPTS certification broadened my offensive capabilities, made me better at my job, and had me re-evaluate what I thought I knew. It was a phenomenal introduction to penetration testing techniques and best practices and a great learning opportunity overall.

![My CPTS cert](/assets/images/cert-cpts.png)_My CPTS Certification_