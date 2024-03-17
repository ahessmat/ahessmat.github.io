#### Introduction to MSSQL/SQL Server

This section is just a primer for the content to follow. It highlights different tools for interacting with MSSQL databases specifically, namely `SQLCMD` (Windows) and `MSSQLClient.py` (Linux). The section has a single exercise which engages the student's ability to perform nuanced MSSQL queries. This is a trivial section, especially if you're already familiar with MSSQL.

#### Boolean-based SQLi

If you've never been introduced to the topic of boolean-based SQLi, then there's some good learning to be had here. Otherwise, this section should feel pretty familiar and be executed pretty quickly. The exercises are relatively trivial to perform, especially since they provide some python scripting to automate retrieving the answers for you. For me, I really liked having the `Optimizing` subsection, which discussed ways for speeding up the query process (and introduces some little Computer Science algorithmic considerations in the process).

#### Time-based SQLi

I'll admit, I was really hesitant about going into this section; previous encounters with time-based SQLi have always been a drag, especially using SQLmap. They usually amount to some agonizing exercises of wait-and-see. Fortunately, this section was really nicely laid out and - with the deliberate absence of SQLmap - made quite quick. I think the longest subsection were the **Out-of-Band DNS** exercises, but that's only because I took some time to try and mess around with the multiple alternative options presented by the section as a kind of self-imposed "extra mile" set of exercises. Altogether, this is a pretty neatly crafted section.

#### MSSQL-specific Attacks

This module looks at some specific (mis)configurations that MSSQL can have that can be exploited to perform additional attacks on the server. Most of what's covered here I've seen in other trainings (e.g. ZeroPointSecurity's CRTO); that said, the **File Read** subsection introduced some functionality I hadn't been previously introduced to which enables appropriately-permissioned users to read arbitrary files from a system. That was really neat to learn!

