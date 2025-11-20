#### Identifying Vulnerabilities

This was an interesting section. Unlike related modules like **SQL Injection Fundamentals**, **SQLMap Essentials**, **Introduction to NoSQL Injection**, and **Blind SQL Injection**, this section is *less* focused on SQL injection and more about finding potential vulnerabilities via Whitebox code analysis. Much of what you're doing in this section excersie-wise is pretty trivial to accomplish, but there's some nice introduction that goes into evaluating Java code (namely: *.jar files); you get introduced to tools like **fernflower** and **JD-GUI** to that end. I did find that I couldn't recreate the steps outlined in the **Live-debugging Java Applications** subsection and ultimately gave up trying since there was no accompanying exercise and little else to go off of on the Discord. That's a shame, because the premise behind it sounded really interesting.

#### Advanced SQL Injection Techniques

This section was a natural extension off of what was presented in the previous one, focusing on our ability to understand nuances in the SQL injection vulnerabilities present within the target application by way of whitebox assessments. Unfortunately, I couldn't get the first exercise working in the **Common Character Bypasses** subsection; the specified endpoint appeared accessible only if you already were logged into the application (and we weren't supplied any credentials for the web app); I had to step over that subsection and use the vulnerability present in the next subsection (**Error-Based SQL Injection**) instead in order to answer it. Incidentally, the **Error-Based SQL Injection** section would have been made much easier if I had been able to get the **Live-debugging Java Applications** section working; instead, I had to draft my own Java code to reverse-engineer the correct answer; I reached for https://www.programiz.com/java-programming/online-compiler/ to help make the mock-up, which turned into something like this:

![](/assets/images/2024/asi1.png)

Note: we had to draft a new `md5DigestAsHex()` method because Progamiz doesn't include the Spring framework `DigestUtils` library.

#### PostgreSQL-Specific Techniques

This section presented some novel ways to go about achieving RCE on a PostgreSQL server. However, there is one detail in the **Command Execution** subsection that I found to be very frustrating; in it, they detail how PostgreSQL is can import custom extensions which - in turn - can be leveraged to achieve RCE. However, such extensions *must* be compiled using the same version of PostgreSQL - and this was the frustrating bit. I found discovering, installing, and using old versions of PostgreSQL was not very intuitive, so I've documented those efforts below:

1. Edit your apt list repositories to include the `bullseye` list
  1. `sudo nano /etc/apt/sources.list.d/debian.list`
  2. `deb http://deb.debian.org/debian bullseye main`
2. Update your `apt` cache.
  1. `sudo apt update`
3. Install the requisite version.
  1. `sudo apt install postgresql-server-dev-13`
4. Confirm that the version exists on your system. It should list a `13` directory (in addition to whatever default version of postgresql you have)
  1. `ls /usr/lib/postgresql/`
5. Ensure the `pg_config` command is pointed at your newly-installed version of postgresql:
  1. `export PATH=/usr/lib/postgresql/13/bin:$PATH`
  2. `pg_config --version`

This should enable you to perform the commands necessary for the subsection.
