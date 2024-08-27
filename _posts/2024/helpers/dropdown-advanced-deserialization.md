#### Identifying Deserialization Vulnerabilities

This section was a little heavy for me, having not worked extensively with .NET applications very much. Consequentially, there was a lot of tangents and documentation that were pulled up to get oriented more generally. The module provides a minimal job of orienting you as a student to the tech stack, so if you're like me you might do a lot of pausing through this subsection to figure out architecturally what's happening.

Moving past that, this section introduces working with Jet Brains dotPeek and/or ILSpy for decompiling .NET applications from their intermediate MSIL format. Initially, I was pretty retiscent about standing-up a dedicated Windows 10 VM just to facilitate the module; as such I reached for a clone of ILSpy for Linux that I could run on Kali: `https://github.com/icsharpcode/AvaloniaILSpy`. In time I found however that standing up such a VM was the most practical for me (vs. using the supplied one given at the **Decompiling .NET Applications** subsection), given how slowly I progressed through the module overall; this let me walk away and return to the training hours (or days) at-a-time without losing progress such a configuration also helped facilitate troubleshooting malicious payloads (i.e. if a payload worked on a defaultly-configured Windows 10 VM out-of-the-box, I figured it would reasonably work in most cases on HTB).

Most of the exercises are pretty trivial to perform, with the one exception being what's found in **Debugging .NET Applications**, which requires *considerable* setup in order to facilitate. That said, the exercise is pretty well spelled-out step-by-step in the subsection. So while it's complicated and nuanced, it's relatively straightforward.

#### Exploiting Deserialization Vulnerabilities



This section was where having a dedicated Windows 10 VM setup on an internal network with my Kali VM really paid off. The first exercise presented in