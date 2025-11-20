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
