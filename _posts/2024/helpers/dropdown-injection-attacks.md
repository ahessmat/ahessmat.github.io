#### Introduction to Injection Attacks

This module kicks off with more narrowly framing the lesson to a particular set of technologies: XML Path Language (XPath), Lightweight Directory Access Protocol (LDAP), and PDF-generators. For folks more interested in command injection more broadly, the Academy offers a distinct `Command Injection` module. 

#### XPath Injection

The section is the longest in the module, describing a variety of ways that the XML language can lend itself to abuse. However, some of the methods feel relatively derivative: the **XPath - Authentication Bypass** was *very* similar to SQL injection (albeit with some minor syntactic differences) and  **XPath - Data Exfiltration** was likewise similar (albeit with a little LFI thrown in).

The **XPath -Advanced Data Exfiltration** and **XPath - Blind Exploitation** subsections were where the real learning value of the module resides. There is a lot of really interesting material to mull over and perform in the respective exercises that make them really worthwhile.

#### LDAP Injection

This section was likewise pretty straightforward to perform; I think the real value to me was having some handy references to LDAP syntax, which I often trip over and lose a lot of time on in formatting.

#### HTML Injection in PDF Generators

This section felt pretty niche to me; interesting to be sure, but niche all the same. The gist of it revolves around exploiting vulnerable PDF generation capabilities that may be present in web apps such that input is interpreted/executed as JavaScript code. The kinds of attacks you can perform are therefore likewise derivative to whatever you can maliciously perform with injected javascript (e.g. Server-Side XSS, SSRF, LFI, data exfiltration, etc.). I thought this was interesting, but wasn't really sure how applicable testing for this vulnerability might be outside of Hack The Box's gamified environments.