#### Whitebox Pentesting Process

This section of the module does not have any exercises. However, as tempting as it might be to click through the material, I'd urge students to pause a minute and read through what's listed. A lot of what's described covers processes similar to what I've encountered professionally either as a penetration tester or in application security engineering. I feel like this portion of the module and others like it (e.g. **Documentation & Reporting**) are glazed over as they distract from the "fun" of technical exploitation.

#### Code Review

For me, this was an interesting section since my job involves a considerable amount of code review. I think there were some great points made, including highlighting some of the strengths/weaknesses of utilizing vs. over-relying on services like **Github Copilot**. There's also a cursory dip into running **Node.js** applications (although far from anything you'd need to be proficient). Since the instructions are rather sparse on installing it on Kali linux systems, [I'll include a nice link here that will take care of you](https://deb.nodesource.com/).

#### Local Testing

This was surprisingly challenging. While all of the exercises for the section provide either hints of "Reveal Answer" buttons, the challenge is less in arriving at the correct answers (which is trivial), but in arriving at the correct payloads to achieve those answers. There was a lot of frustrating elements to understanding why particular methods of execution worked and others did not. For example, I knew commands were running with `exec`, but couldn't see the output until I substituted it with `execSync` paired with the `toString()` method. By-and-large, if you're stuck in a subsection, look ahead at the next one and you'll generally arrive at the commands necessary to achieve the correct answers.

#### Proof of Concept (PoC)

This subsection was both fun and challenging, building off of the toy NodeJS app that was introduced at the start of the module. The progression here is about making more complex payloads/exploits, but the problems are quite open-ended, allowing you to concieve of your own approaches. I found that my biggest point of friction up until this moment was sorting out the quotes/double-quotes in my payload, so I ended up base64-encoding the entire thing, putting it within a b64-decoding wrapper, and passing that to the the exploit. Something to the effect of:

![](/assets/images/2024/whitebox1.png)

Overall, this was great!
