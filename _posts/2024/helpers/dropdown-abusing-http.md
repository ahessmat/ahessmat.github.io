#### Introduction to HTTP Misconfigurations

This part of the module is just a high level preview of the content to come: Web Cache Poisoning, Host Header Attacks, and Session Puzzling. There are no associated exercises.

#### Web Cache Poisoning

This is a phenomenal section in the module, thoroughly covering details of the attack. **Advanced Cache Poisoning Techniques** had good exercises in particular; the exercises that were presented were very similar to the walkthrough material, but had just enough variation so as to force you to step through the discovery process from square 1. My one sticking point was during **Tools & Prevention**, where you're required to download and use the **Web-Cache-Vulnerability-Scanner (WCVS)**. At the time, my version of ParrotOS was tied with GLIBC version 2.31 (you can likewise discover your version by running the `ldd --version` command); unfortunately, the latest binary release of WCVS would throw errors as a result, calling for GLIBC_2.34 at least.

![](/assets/images/wcvs1.PNG)

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

