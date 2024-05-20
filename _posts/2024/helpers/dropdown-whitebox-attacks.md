#### Prototype Pollution

This section was was great. It talked about some really interesting mechanisms for attacking a web application by way of JavaScript Objects and - more specifically - prototypes. There are three exercises to the section, each engaging the content in a new and interesting way. I found the exercises to be a little frustrating at parts; for someone entirely new to this kind of vulnerability, there's enough information present in the section to conceptually grasp at what's being talked about but just enough omitted that you will likely have to consult some outside material to supplement it. One of my favorite tool-takeaways that was introduced was BurpSuite's **DOM Invader**.

#### Timing Attacks & Race Conditions

This section was well written. It begins with orienting the student more generally on race conditions that they might recognize from other CTF-like challenges at the OS-level, then demonstrates how such Time-of-Check, Time-of-Use (`TOCTOU`) vulnerabilities might emerge within web applications. Along the way, students are provided some example python scripting to tool about with, as well as a `BurpSuite` extension (`Turbo Intruder`).

#### Type Juggling

Like the other sections before it, this was a really well-developed section within the module. `Type Juggling` vulnerabilities arise when loose comparisons are made (and data type values are assumed - i.e. `0 == null`); this can lead to some interesting bypasses and other issues. While couching the lessons in PHP, efforts are made throughout the module to highlight syntactic differences that exist in other languages as well. One of the really valuable resources supplied is a table of equivalent values interpreted by PHP; this was really useful for a number of the exercises.