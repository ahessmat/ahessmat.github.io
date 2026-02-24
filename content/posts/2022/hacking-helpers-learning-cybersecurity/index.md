---
title: "Hacking Helpers"
draft: false
date: 2022-02-06
summary: "TEST"
tags: [resources]     # TAG names should always be lowercase
aliases: 
  - /posts/hacking-helpers-learning-cybersecurity/
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
summary {
  cursor: pointer;
}
</style>

There are a lot of resources available online to learn cybersecurity. You can watch lectures recorded from top universities, practice your skills in labs, and much, much more. This content is often at little or no cost to you and supplements your formal education/certifications. Below is a list of some of the resources that I've come across and used in the course of my career. Click on the any of the dropdown menu options below to see the respective resources.

**Updated February 2025**

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Hands-On</summary>

## Hands-On Resources

Sometimes the best way to learn cybersecurity is by just working with the tools and technologies themselves. Whether you want to code, hack, or just learn the basics, these platforms and services are built to drop you in the thick of it and get your hands dirty.

So what do you want to learn?

### The Command Line

For a lot of people, most interactions with computers and applications is through some kind of Graphical User Interface (GUI), this includes things like a smartphone's touchscreen, Windows Desktop, web browsers, etc. However if you're going to become involved with cybersecurity professionally, you'll need to get comfortable using a command line interface (CLI) terminal.

* [OverTheWire](https://overthewire.org/wargames/bandit/): specifically, the "Bandit" series offered by OverTheWire is an excellent way to gamify your learning in getting introduced to the Linux CLI with a security flair. Like many of the resources listed here, it's completely free.
* [LearnEnough](https://www.learnenough.com/command-line-tutorial): Michael Hartl's tutorial to the Unix command line is a guided introduction to using CLI, complete with exercises, all for free.
* [LinuxJourney](https://linuxjourney.com/): This offers a simpler walkthrough of CLI and quite a bit more. It's lean, pretty to look at, and all completely free.
* [PowerShellTutorial](https://powershelltutorial.net/): most people getting started learning CLI tend to prioritize learning Unix OS CLI, but you'll probably want to also gear up on Powershell for Windows environments; PowerShellTutorial.net is a great resource to that end.
* [Cisco Learning Academy: Linux Essentials](https://www.netdevgroup.com/online/courses/open-source/linux-essentials): for several years now, Cisco's Learning Academy has made this course available for free. It's a phenomenal guided learning course for getting into the thick of how to use Linux CLI.

### Coding

While the vast majority of roles in cybersecurity don't explicitly require you to know how to *write* good code, your professional aptitude would almost assuredly benefit from being able to *read* it. Fortunately, there's a lot of resources online dedicated towards improving your programming-language comprehension.

* [Code Academy](https://www.codecademy.com/): This is one of the most popular freely-used resources available for learning the syntax of programming languages. It has structured courses to provide step-by-step instruction on understanding common object-oriented programming (OOP) concepts, such as methods, classes, and data structures.
* [The Odin Project](https://www.theodinproject.com/): This is an open-source curriculum for learning full-stack web development. It assumes no knowledge of you as a student in walking you through the process to developing your own web application.
* [LeetCode](https://leetcode.com/): This is less of a resource about how to learn to code and more of how to learn to perform coding *interviews*; this site presents an array of toy problems for you to implement solutions to in your choice of programming language(s). If you're planning on applying to work at Big Tech, this is a resource you cannot ignore.
* **The Python Challenge**: This is a gamified series of puzzles that were built to encourage learning Python through practical application.
* [SQL Murder Mystery](https://mystery.knightlab.com/): This is my favorite resource to recommend folks getting innoculated to SQL syntax. It's a gamified murder mystery, and the only way to solve the mystery is through the use of SQL queries. The initial steps are quite basic, but getting to the end requires understanding and stringing together increasingly complex SQL statements.
* [Sad Server](https://sadservers.com/scenarios): This was a neat find recently; it helps promote code literacy by setting up some small debugging problems (and a handful of classic CTF challenges) for you to puzzle through.

### General Cybersecurity Training

Beyond learning just the above fundamentals, there are a number of services and platforms that cater to cybersecurity skills more narrowly.

* [CTFTime](https://ctftime.org/): This is a site that aggregates online Capture-the-Flag (CTF) stylized cybersecurity competitions. If you are unfamiliar with CTF events, they serve as small-scale competitions that often develop/challenge technical skills. Most are free and some offer rewards; the most noteworthy of them all is the annual [DEFCON team-vs-team event held in Las Vegas](https://defcon.org/html/links/dc-ctf.html). For those just getting started you might consider the more approachable [PicoCTF](https://picoctf.org/) which is geared towards high-school and college students.
* [TryHackMe](https://tryhackme.com/): This is a platform that sets up various online "rooms" that focus on teaching/introducing different exploits or vulnerabilities. Great for walking novices through difficult concepts.
* [Hack The Box](https://www.hackthebox.com/): A platform that stands up a rotating series of intentionally vulnerable targets for anyone to compromise. They also offer more diverse environments with their ProLabs and Battlegrounds offerings for a fee.
* [Hack The Box's Academy](https://academy.hackthebox.com/): This is a parallel service offering to Hack The Box's main platform. It offers catered guided learning to a great number of topics, but requires money to fully access. I resoundingly endorse this training platform, especially for individuals who qualify for the student subscription discount.
* [LetsDefend](https://letsdefend.io/): A similar platform to Hack The Box, but with a defensive flair. Instead of compromising vulnerable machines, you are required to investigate tickets denoting attacks on a network you need to defend.
* [Pentester Academy](https://www.pentesteracademy.com/topics): This platform offers a slew of offensively-oriented trainings. Requires a recurring subscription to access its content; they recently transferred the administration of this function to INE, which is a massive improvement.
* [Portswigger's Web Academy](https://portswigger.net/web-security): This is the spiritual successor to Pinto's "The Web Application Hacker's Handbook". This is the most in-depth, freely available, web app vulnerability training out there. The content is geared specifically towards using Burp Suite, but other tools are viable.
* [Yes We Hack - Dojo](https://dojo-yeswehack.com/learn): This is a nice complementing resource to Portswigger, offering a monthly challenge to keep things fresh.
* [pwn.college](https://pwn.college/): This platform is utilized by Arizona State University (ASU) to teach an array of material, from reverse engineering and privilege escalation to binary exploitation and systems security.
</details>
</div>

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Podcasts</summary>

## Podcasts

Sometimes it helps to talk things through in order to learn cybersecurity. For a technically-grounded subject, cybersecurity can be challenging to relay in just the audio medium; however, there are a number of podcasts that really work well in either being informative, fun, or both. Below are several mini-reviews of ones I listen to:

* [**Compiler**](https://www.redhat.com/en/compiler-podcast): While this Redhat-hosted podcast is geared towards technology more generally, this is a really well-produced show. I'd like to highlight episode 14 ("How Can Memes Improve Security?"), episode 20 ("When Should Data Die?"), and episodes 23/24 ("Are Big Mistakes That Big Of A Deal?" [Parts 1 & 2]) for folks interested in cybersecurity more specifically.
* [**Cyber by VICE/Motherboard**](https://www.vice.com/en/topic/cyber-podcast): I really wanted to like this podcast for the diversity of subject matters that get brought up, but the unedited conversations between the hosts tend to lead to extended and frequent tangents that I find distracting. However, I really like the "[My First Hack](https://www.vice.com/en/topic/my-first-hack)" mini-series the show performs, where they interview folks 1-on-1 with notable security personalities.
* [**Darknet Diaries**](https://darknetdiaries.com/): This is a really well-produced podcast that touches on all manner of subjects as they relate to hacking, cyber crime, data breaches, and more. I could do without the host's subjectivity interjections, but Jack Rhysider can be credited for making the content more accessible and engaging to a wider audiance.
* [**Hackable? By McAfee**](https://www.mcafee.com/blogs/hackable/): This was a well-produced podcast that explores the various avenues and methods your devices can be compromised (generally at a high-level). They often demonstrate the attacks on the producers of the show, much to their shock and amazement. Unfortunately, McAfee appeas to have suspended production of the show as it hasn't put out a new episode since 2019.
* [**Hacked by Sticks & Stones**](https://www.listennotes.com/podcasts/hacked-sticks-stones-AJQ4DOeq1p2/): This show has pivoted to doing long-form journalism on a variety of cybersecurity-related subjects. The matter is presentable and easy to follow with great audio quality and production. This is one of my personal favorites.
* [**Malicious Life by Cyberreason**](https://malicious.life/): This show offers a mix of topical subjects, conference presentations, 1-on-1 interviews, and other cyber-related matters. It's fairly well-produced, although the host's commitment to using [non-regional diction](https://youtu.be/d8IEhcN9aFo) can get a little grinding.
* [**The Cyber Work Podcast**](https://www.infosecinstitute.com/podcast/): While covering a wider range of subjects, I generally highlight this podcast for its [Career Series](https://www.infosecinstitute.com/podcast/?Type=Career+Series), which helps address the more broader question "What does [job] do?" 
* [**Hard Fork by NYT**](https://www.nytimes.com/column/hard-fork): Like "Compiler", this podcast is not dedicated to cybersecurity but emergent technology at large and its relationship to us as people. I think that this one is compelling in the way that it occupies similar spaces of concern as cybersecurity more generally in being interested in more than just tech specs but its implications/ramifications.
</details>
</div>

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Videos</summary>

## Videos

Like many people, you might turn to video walkthroughs, online personalities, or otherwise entertaining video streaming content from time-to-time. There's a lot that video has to offer someone interested in cybersecurity, so I thought I'd share some of the resources I've engaged:

* [HACKING GOOGLE](https://www.youtube.com/playlist?list=PL590L5WQmH8dsxxz7ooJAgmijwOz0lh2H): This YouTube playlist was produced and published by Google in late 2022. It's a docu-series dedicated to each of the teams that make up Google's cybersecurity arm. It's really well-produced and has a lot of entertaining stories tied in with it.
* [How Hackers Learn Their Craft](https://youtu.be/6vj96QetfTg): This is a presentation done by a Carnegie Mellon professor showing the benefits of Capture-the-Flag training events. Carnegie Mellon is a university in the U.S. that is host to the Plaid Parliament of Pwning, a group that holds the most wins overall (and most consecutive wins) at the DEFCON head-to-head CTF.
* [John Hammond](https://www.youtube.com/c/JohnHammond010): Hammond is a notable figure in cybersecurity for putting together easy-to-follow content across a diverse array of subjects. His channel helps many people learn cybersecurity in a pragmatic way.
* [Mr. Robot](https://www.amazon.com/Mr-Robot-Season-1/dp/B00YBX664Q): This TV Drama is notable for inclusion because throughout its production the show's producers consulted real cybersecurity professionals to better represent them onscreen. Consequentially, it's received a number of accolades for its realistic portrayals.
* [Laurie Kirk](https://www.youtube.com/@lauriewired): Kirk's content is phenomenally in-depth for reverse engineering malware - particularly on mobile devices. Her content is delightfully edited in a retro fashion, and its really informative.
</details>
</div>

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Books</summary>

## Books

Books are wonderful resources to learn cybersecurity. They often dive deep on subjects, enabling you to better understand the given subject-matter. Try checking out your resident library to see what's available locally (or [humblebundle](https://www.humblebundle.com/bundles?hmb_source=navbar) for the occasional cyber-themed bundle of eBooks). Another wonderful suggestion catalogue can be found at the [Ohio State University Cybersecurity Canon](https://icdt.osu.edu/cybercanon/bookreviews). Absent that, consider some of these recommended reads that I've personally read over:

* **Sandworm by Andy Greenberg**: This details the discovery of a Russian GRU hacking unit by way of its developed exploits and attacks in Eastern Europe; it builds upon the author’s earlier work with WIRED magazine, which detailed the NotPetya attack that crippled Ukraine’s infrastructure and cascaded across the globe. At its core, it opens readers to the prospect of cyberwarfare.
* **Ghost in the Wire by Kevin Mitnick**: This is the author’s autobiographical account of their criminal exploits as a phone phreaker and cracker throughout the 80’s and 90’s. While somewhat self-aggrandizing and lacking in any real introspection, it is very clear that – in a technical capacity – the author knew how to “walk-the-walk” so-to-speak. It also offers some insight as to how aggressive the U.S. judicial system can handle cyber crime.
* **The Basics of Hacking and Penetration Testing by Patrick Engebretson**: as a book “aimed at people who are new to the world of hacking and penetration testing”, it offers plenty of interesting things for novices looking to enter the industry. This includes the use and application of assorted tools in the stages of a pentest.
* **The Kill Chain by Christian Brose**: an indirect take on cybersecurity, focusing more on the subject of U.S. national security in its positioning with China. It does examine how technical innovations (such as AI and other autonomous systems) may overturn the American model of national defense.
* **You’ll See This Message When it is Too Late by Josephine Wolff**: This book performs a number of case studies on how organizations have responded to cyber espionage, fraud, and other crimes. It shows that there isn’t really a one-size-fits-all response and that people are quicker to assign blame rather than focus on the victims and damages.
* **Dark Territory by Fred Kaplan**: This book describes the growth of cyber warfare and the extent to which our lives have become inextricably linked to the internet. It backgrounds how various U.S. agencies have been shaped by cyber policy enacted by people with competing interests; this aspect can make the book challenging at times to follow.
* **@War: Rise of the Military-Internet Complex by Share Harris**: Harris details the political mechanisms that were used by various U.S. federal organizations - such as the NSA and FBI - to carry out authority in the domain of cybersecurity. It's a history of preemptive action and response; showing how the federal government can at times be both the biggest player in the space and also the most out-of-touch.
* **Spam Nation by Brian Krebs**: Krebs is probably more well-known for his ongoing blog, [Krebs On Security](https://krebsonsecurity.com/). However, this book examines more closely an area of early fascination by Krebs: the so-called Pharma Wars. It's a narrative of dramatic confrontation between two major underground pharmaceutical businesses (Rx-Promotion and GlavMed) from 2008 to 2010, the people that operated them, and the black market it facilitated.
* **We Are Anonymous by Parmy Olson**: This book is a narrative on the rise and prominence of the online anarchist collective referred to as "Anonymous". Covering a span of time from 1994 through 2012, the author showcases the conditions that fostered such a group, then more narrowly reconstructs the lives of a handful of its participants who later formed the hackvist group, LulzSec. It's a quick, uncomplicated read.
* **The Ransomware Hunting Team by Renee Dudley & Daniel Golden**: This non-fiction work is about a small group's efforts to combat Ransomware globally. The team - a disparate collective of American and European volunteers - are shown as working doggedly to reverse engineer various strains of malware. The work is largely non-technical, blunting the nuances involved in *how* they perform their work and how ransomware operates - favoring higher-level descriptions and handwaving in order to keep the reader's attention squared on the human narrative of the team members (e.g. Michael Gillespie, Fabian Wosar, and Sarah White) and the ransomware's victims.
</details>
</div>

<hr>
<div class="custom-dropdown">
<details markdown=block>
<summary markdown=span>Miscellaneous</summary>

## Miscellaneous

For everything else that doesn't quite so neatly fit into the above.

* [Hackercool Magazine](https://www.hackercoolmagazine.com/): I love this online 'zine, having stumbled upon it in my local library (I don't know who at my local branch discovered/subscribed, but I'm glad they did!). It covers some interesting techniques and emergent exploits, recreating them step-by-step for the reader. Though a small publication, it offers some quality content in its clearly written articles.
* [MIT's OpenCourseWare](https://ocw.mit.edu/search/): the Massachusetts Institute of Technology has made publicly (and freely) available a fair number of their courses. While auditing the coursework won’t count towards college credit (nor confers you a “student” status with the university), the available knowledge is there for getting engaged with Computer/IT fundamentals.
* [Router Alley](https://routeralley.com/index.html): A fantastic resource from Aaron Balchunas for all things related to routing, including guides to Cisco certifications and equipment (though slightly dated). There are a few “Labs” available to help contextualize the book knowledge as well.
* [ICS Security Resources](https://github.com/hslatman/awesome-industrial-control-system-security): This GitHub repo is an awesome collection of resources to help orient someone towards Operational Technology (OT).
* [Pocket Admin](https://github.com/krakrukra/PocketAdmin): I love this keystroke injection device. This is a cost-effective alternative to Hak5's Rubber Ducky, even going so far as to provide you the instructions for building one yourself. The creator of the technology used to be able to sell the assembled tech directly to you, but - in residing in Russia - can no longer do official sales to Western buyers due to sanctions.
* **Throwaway Email Accounts**: sometimes you just need a throwaway email account. For those instances, I love tapping into either [10 Minute Mail](https://10minutemail.com/) or [TempMail](https://temp-mail.org/en/). 
* [CIDR Visualizer](https://cidr.xyz/) is a wonderful website to help visually understand subnets and network address spaces.
</details>
</div>
