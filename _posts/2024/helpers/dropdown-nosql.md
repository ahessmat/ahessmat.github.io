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