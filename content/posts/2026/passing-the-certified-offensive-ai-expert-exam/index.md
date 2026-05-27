---
title: "Passing the Certified Offensive AI Expert (COAE) Certification Exam"
draft: true
date: 2026-05-21
summary: "A brief writeup on the experience of passing HacktheBox's latest certification exam"
tags: [exam,htb,certification]     # TAG names should always be lowercase
---

Earlier this year, HackTheBox (HTB) announced its latest certification - its first in examining the intersection of artificial intelligence (AI) and security. The [Certified Offensive AI Expert](https://academy.hackthebox.com/preview/certifications/htb-certified-offensive-ai-expert) (COAE) credential made for a natural milestone in my ongoing efforts to cross examine AI in the cybersecurity space.

<center>
<blockquote class="twitter-tweet"><p lang="en" dir="ltr">If you think securing an AI model starts and ends with the prompt, you are already behind 🏃‍♀️ <br><br>Attackers are finding ways to compromise the system from the initial training data to the final output. We are breaking down the major AI attacks you cannot afford to ignore 👇 <br><br>Level… <a href="https://t.co/9EVAfJFNqY">pic.twitter.com/9EVAfJFNqY</a></p>&mdash; Hack The Box (@hackthebox_eu) <a href="https://twitter.com/hackthebox_eu/status/2048749083083374817?ref_src=twsrc%5Etfw">April 27, 2026</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
</center>

Given my previous experiences with HackTheBox's training offerings with the [CPTS]({{< relref "/posts/2023/passing-the-certified-penetration-testing-specialist-cpts-certification-exam" >}}) and [CBBH]({{< relref "/posts/2022/passing-the-certified-bug-bounty-hunter-cbbh" >}}) (now [CWES](https://academy.hackthebox.com/preview/certifications/htb-certified-web-exploitation-specialist)), I had my expectations set pretty high for this exam's content.

## COAE Training Material: HTB Academy

Arguably, the greatest value for pursuing this certification isn't the credential itself, but the accompanying compulsory training modules hosted on HackTheBox's Academy platform. As of the time of writing this, the COAE's training curricula is coupled with the content found within the Academy's [AI Red Teamer path](https://academy.hackthebox.com/path/preview/ai-red-teamer), which - as of writing this - incudes such topics as:

* Fundamentals of AI
* Applications of AI in InfoSec
* Introduction to Red Teaming AI
* Prompt Injection Attacks
* LLM Output Attacks
* AI Data Attacks
* Attacking AI - Application and System
* AI Evasion - Foundations
* AI Evasion - First-Order Attacks
* AI Evasion - Sparsity Attacks
* AI Privacy
* AI Defense

HTB Academy is a really stable and feature-rich training platform. If you're not otherwise familiar with it, within its various "modules" HTB offers guided training to topics, typically subdivided into pertinent sections and paginated by topic. For example, the `Fundamentals of AI` module splits-up its training into the sections of Supervised, Unsupervised, and Reinforcement Learning Algorithms (among several others); within the Supervised Learning Algorithm section you're meant to drill down deeper into pertinent topics like Linear Regression, Logistic Regression, Decision Trees and Naive Bayes: topics which classically make up the foundations for the Supervised Machine Learning. Many sections will have a hands-on practical application of what was learned, with an overarching skills assessment for the entire module marking the close (usually creatively applying what was covered in the guided sections).

### Content Covered

At 12 modules, the amount of ground to cover is quite a bit less than some of HackTheBox's other certifications (22 for the CWES, 28 for the CPTS); however, I would argue that some of the content covered is *substantially* more dense than what you might encounter in some of the Academy's other offerings. HackTheBox's curricula is quite ambitious in seeking to condense multiple semesters-worth of Computer Science education into its training. While some modules - like the `Prompt Injection Attacks` - are fairly easy to understand and execute, there are several which include some pretty advanced mathematics (or at least, high-level mathematical notation than what most who explore the space of cybersecurity bother with learning). For example, consider the following formula HTB presents on learning about AI Evasion (and more narrowly, L1 Proximal Operators):

{{< katex >}}
$$
s_{\lambda}(z_i) =
\begin{cases}
z_i - \lambda i & \text{if } z_i > \lambda \\
0 & \text{if } |z_i| \le \lambda \\
z_i + \lambda i & \text{if } z_i < -\lambda
\end{cases}
$$

Fortunately, in most cases HTB splits apart what's necessary for understanding the underlying concepts from engineering such methods in code; most of the time, HTB has done the courtesy of already drafting much of what you need to do for you (if only requiring you to stitch-together the disparate code blocks they pre-define for you). While I'd encourage anyone who is genuinely interested in security research in AI to grapple with the math, it's not explicitly necessary to get through the modules and pass the certification. Ironically, it would not surprise me to learn of students cognitively offloading the lessons imparted to an LLM to handle.

I think the best lessons HTB has to offer within the AI Red Teamer Academy path are those that deal with attacking the model directly (either in their training corpus data or in creating shadow adversarial models), as these explore more into the domain of AI Security research advancements. However, a valid criticism that has emerged from HTB's customer base has been how applicable these topics are to real-world test events; how often - for example - is a Pentester going to be able to perform a Jacobian-based Saliency Map Attack (which requires white-box transparency of the underlying model)? There are also some instances where I would question just how fundamental some of the explored research really is; some of the topics covered in the more complex modules felt like they were cherry-picked as an interesting research edge-case vs. something representative of security research at-large. A lot of time is exhaustively spent looking at various ways of attacking image classifier models, but none is spent on vulnerabilities present in models used for video and audio media; I was surprised that there was nothing concerning how to perform deepfakes of someone's voice for phishing, for example.

By contrast, exploiting model behavior by way of prompt injection wasn't as interesting or challenging (but are more in-line with what classic pentesting might aim to accomplish); there's plenty of content there for those who haven't explored these topics before, but I'd argue there are vendors who present a more diverse range of ways to attack such models (and under more hardened conditions). For those interested in those topics, I'd assert better opportunities to explore those kinds of attacks are available through [Gray Swan](https://app.grayswan.ai/) and [Lakera](https://gandalf.lakera.ai/baseline).

One thing you shouldn't expect to have integrated into the training (and is largely treated as as known knowledge by the student) are some of the more traditional security vulnerabilities that AI models might exacerbate. Students enrolling into the AI Red Teamer course are just presumed to know/understand command injection, path traversal, and cross-site scripting, for example. If you don't know how to do these things, you probably should consider walking back from this training offering until later.

## COAE: The Exam

HTB's terms of service explicitly prohibit me from disclosing details about the exam that they don't otherwise share themselves; as such, there's not much more I can say that others haven't. If you've taken any of HTB's other exams, their format should be quite familiar to you: you're put into a scenario with a fictional customer who - through a detailed Letter of Engagement - scopes the work you're meant to perform. Benchmarking that work are a series of tasks (which are met through the attainment of CTF-like flags), which help point you in the direction your work is meant to take you. Each flag is worth a certain number of points, with the minimum passing threshold being 85 out of 100 points. In addition to simply scoring points, you are required to submit an after-action report (not unlike what you might for a real-world test engagement) detailing your various findings and exploit chains.

The exam's testing environment is available to you for up to 7 calendar days, which allows you to comfortably arrange your applied time testing around other competing things that might be happening in your real life. Unlike some of its other exams, HTB doesn't make use of a VPN for you to engage the test environment (simply configuring your /etc/hosts file to point at the appropriate domains and subdomains will suffice).

### Exam Experiences

For as much as I liked HTB's Academy platform for its quality of training materials and exercises, I feel conflicted about the COAE exam and certification.

#### Is it hard?

I felt that this exam was much easier than the exams put forward for the CPTS and CWES exams, respectively. Whereas it took me multiple attempts to pass the CPTS and CWES exams, I finished the COAE exam well within the alloted time window and submitted it days ahead of the deadline. Overall, I'd argue my experiences with HTB's weekly machine releases to be of greater challenge than the exam environment provided.

One of the reasons I feel that the exam is so much easier than the others is owing to its narrow scope of testable learning objectives. For the CPTS/CWES, if you get stuck you're often pouring over massive indexes of notes trying to discern what you may have overlooked or failed to consider; at 28 and 22 modules worth of content respectively, there's a lot of potential avenues to explore and possible vulnerabilities to check and iterate upon. At only 12 modules worth of content in the aligned AI Red Team path, there's just less to have to consider for the COAE exam (with some of it blatantly apparent as to what you're meant - or not meant - to consider).

I also felt that the overall scenario architecture was more convoluted with the CPTS/CWES exams; the attack surfaces for those exams had a lot of sprawl to them. This helped add layers of uncertainty to those exams, which both elevated their difficulty and contributed to their realism; you could never be sure if you were stuck because you had incorrectly implemented an exploit, because you had overlooked a class of vulnerability covered from the instructional materials, or because you hadn't yet uncovered a crucial piece of information hidden elsewhere in the test environment. With little exception, this wasn't my experience with the COAE exam.

#### Environment Instability

[Julian Gomez mentioned this in his own review of the exam](https://juliangr.com/blog/certification-review-htb-coae/#environment-and-exam-stability), but I had to actively battle the test environment itself while conducting my exam. BurpSuite - for whatever reason - regularly drops requests in its proxied browser (rendering its classic white-and-orange site with a "No response from server" message coming back). While refreshing the page was often remedy enough, it made for quite a frustrating experience in enumerating content served over the web.

Another issue I encountered was that my test environment was actually broken at one point; without going into too much detail, a key backend service had become downed and I was unaware of whether that was deliberately the case or not. I lost a whole day enumerating the exam environment trying to figure out what had happened - and even got assurances from HTB's own support staff that nothing was wrong - before resetting my exam environment and resolving the issue.

{{< figure src="help-ticket.png" alt="HTB support ticket" figureClass="flex flex-col items-center" >}}

Arguably, this is user-error on my part; this isn't the first exam I've come across that has had issues fixed by an environment reset (hence why I had suspicions that resetting might work to begin with). However, it's worth calling out just in case you might likewise encounter such trouble. I have little doubt that - in time - HTB will be able to iron-out these issues.

## Is it worth it?

This is an issue that I think all of HTB's certifications struggle with justifying. Outside of upskilling, the value of a certification for most end consumers will be in how well its attainment will promote their own individual employability. It's no secret that there is [no shortage of vendors and certification offerings available](https://pauljerimy.com/security-certification-roadmap/) for people to spend their time/money on acquiring, but only [a narrow subset of them actually matter to individual employers]({{< relref "/posts/2023/what-certifications-should-you-get" >}}). 

Hack The Box is still relatively new to the space - its first available certification (the CBBH, now CWES) was released in 2022 and as of the time of writing this post only has been passed by about 2k people (it's most-issued certification, the CPTS also released in 2022 is doing only slightly better, at just shy of 3k people); but their exclusivity - which some market as a sign of its higher-caliber/standards - hurt their marketability for cert-holders, because then its not a quantitatively strong enough signal for employers to filter against. For comparison's sake, OffSec said in 2025 that "[tens of thousands of people have achievd the OSCP certification](https://www.offsec.com/blog/champion-oscp-for-your-team/)"; CompTIA championed how [more than a million people attained their Security+ cert](https://www.comptia.org/en-us/about-us/news/press-releases/1-million-strong-how-comptia-security-shapes-cybersecurity-skills-around-the-world/) in 2025; in 2024, ISC2 announced their [CISSP certification had been attained by more than 165,000 people worldwide](https://www.isc2.org/Insights/2024/03/ISC2-Celebrates-30th-Anniversary-of-CISSP-Certification). I'm aware that I'm making apples-to-oranges comparisons in some of these cases (e.g. the target demographic for the Security+ is far less technical, less offensively-oriented, and more early in their career than what HTB's certifications generally target), but the point is that there is significantly broader appeal for these other certs and vendors than what HTB can offer with theirs.

Finally, I'll hazard that professionalized security research in the AI space is largely not driven by certifications (vs. paper-publishing, conference presentations, etc.). Ultimately, I'm not really convinced that attaining the COAE certification will significantly improve one's employability at getting into AI Security. I think the real winner of attaining one of HTB's certs is HackTheBox itself: the certs serve as a draw to their Academy platform (which - again - I think is incredibly well-curated, very accessible, and has a wonderful community backing it) and to engage/explore content on the platform you might not otherwise consider.

## Closing Thoughts

This year has really kicked-off my exploring all manner of AI-related security studies and I was quite pleased with the materials provided by Hack The Box in support of the COAE certification. The content to learn is surprisingly involved and has quite a bit of depth to it; the real value to the COAE is in that training. But where HTB seeks to explore how security concerns can emerge in a model's conception and development, there is some struggle with the COAE exam implements those in practice. Overall, while I'd encourage people interested in the intersectionality of AI and cybersecurity to review the Academy content, you can probably save your money on a voucher for the exam.
