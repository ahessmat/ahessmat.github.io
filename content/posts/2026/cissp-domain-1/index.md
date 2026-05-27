---
title: "Studying for the CISSP: Domain 1"
draft: false
date: 2026-05-25
summary: "My notes on studying for the CISSP, domain 1"
tags: [exam,certification,resources]     # TAG names should always be lowercase
---

## Introduction

ISC2's flagship certification, the Certified Information Systems Security Professional (CISSP) is arguably the [most oft-requested certification across all job roles in cybersecurity]({{< relref "/posts/2023/what-certifications-should-you-get" >}}). It's a bear of an exam to study for, spanning an enormous breadth of testable material and being administered as an adaptive exam (meaning the exam's algorithms identify which areas you struggle in most and serves you questions in those areas more often than your stronger ones).

While I've met [the exam's years-of-experience prerequisite](https://www.isc2.org/certifications/cissp/cissp-experience-requirements) for several years now, studying for this exam has always felt like a chore to me; each time I've cracked open the book to study, I've been put to sleep (sometimes literally) from how dry and abstract the material has struck me as being. However, I want to turn over a new leaf; I want this cert - for as much as I might point to the myriad of other credentials I have, I recognize attaining this certification can only benefit my employability under conditions where [finding work can be extraordinarily challenging]({{< relref "/posts/2025/where-are-all-the-cybersecurity-jobs" >}}).

To that end, I'm going to catalog my lessons learned from the [Destination CISSP](https://www.amazon.com/Destination-CISSP-Concise-Rob-Witcher/dp/B0D37YPGPZ) (DCISSP) study materials. As stated above, these posts are largely going to be self-serving, since I'm trying to use the act of blogging to reinforce committing the lessons-learned to memory. That said, I'll highlight nuances and actions where appropriate during this series that I found helpful.

So, without further ado...

## Domain 1

Domain 1, *Security and Risk Management* takes me back to my GRC functionary days. It's full of quasi-useful abstractions and concepts for organizing how we present and frame cybersecurity in ways that - I feel - tortuously contort the engineering discipline into more business-compatible terminology. I have read (and re-read) this section ad nauseaum because it's dominated by a bunch of very forgettable and similarly-named terms; you'd be forgiven (by me, not by the CISSP exam) for mixing up the 44 different acronyms introduced in this domain alone.

> [!NOTE]+ See how many you can recognize!
> CIA, CSP, ITAR, EAR, GDPR, 3P, IP, SD, PII, PHI, PCI, SPI, OECD, SA, GLBA, HIPAA, SOX, COPPA, CCPA, PIPEDA, PDPL, PIPA, DPIA, NERC CIP, NIST, ISO, BIA, NDA, NCA, SLA, ALE, SLE, AV, EF, ARO. PDCA, RMF, COSO, ERM, STRIDE, PASTA, DREAD, SCRM, and SLR

Some of these I'm quite familiar with, either as a result of having studied the acronym in the past or having had direct work experience with, but there's several that have quite a bit of depth that - I feel - are probably worth teasing out.

## Due Care vs. Due Diligence

Not an acronym, I know. But gun-to-my-head: I always mix these two up (and whenever they are referenced in professional context, they're usually interchangeable or said as a pair), but the exam *really* cares about the distinction.

### Due Care

Accountable protection of assets based on goals/objectives of the organization.

**THINK**: ACTIONS.

An example is the act of doing a pentest and remediating the findings.

### Due Diligence

Ability to prove due care to stakeholders.

**THINK**: PROOF.

An example is the paperwork and audit trail showing that findings are remediated in a cost-effective manner.

## The Legal Ones

Out of all the acronyms relating to laws/regulations, DCISSP calls out only `GDPR`, `SA`, `DPIA`/`PIA` and `OECD` as worth knowing in detail. In brief: **The GDPR is an EU bellwether privacy law wherein data subjects have the right to lodge a complaint with independent supervisory authorities (SA), with guidelines for privacy established by the Organization of Economic Cooperation and Development (OECD)**. Article 35 of the GDPR includes a provision for **Data Protection Impact Assessments (DPIA)**, to determine if personal data is being protected appropriately and to minimize risks.

DCISSP then provides an enormous table on Privacy Impact Assessment steps, but I'm going to just set that aside for my first pass on this material.

While we're at it, there's also pages dedicated to delineating the conceptual differences between `polices`, `procedures`, `standards`, `baselines`, and `guidelines`. From my time working GRC, policy and procedures I understand pretty well, so I'll focus on the last 3:

* A `standard` is a specific hardware/software solution, mechanism, or product (i.e. using a certain anti-virus solution might be considered an organizational standard).
* A `baseline` is a minimal configuration for security mechanisms/products (i.e. an OS image must be at least baselined against a select criteria).
* A `guideline` is just a suggestion or recommended action, but not an enforceable one.

## Risk Management Terms

Again, a lot of my existing work history is doing a lot of the heavy-lifting in familiarity with the content. I feel comfortable delineating differences and relationships between threats, vulnerabilities, and risk. Things take a nosedive however when it comes to recalling the **Annualized Loss Expectancy Calculation**.

```
ALE = SLE (AV x EF) x ARO
```

At a high-level, I get what these variables are standing in for: its an equation that produces an (estimated) dollar value of the cost to the organization of risks materializing across the year. The math is pretty straightforward:

* You get the dollar value of your assets - the asset value (`AV`).
* You multiply AV by the percentage of those assets that would be affected (i.e. if a snowstorm takes out 3 of 5 facilities, then that asset would be considered 60% exposed - the `exposure factor`).
  * The product of AV x EF is the single-loss expectancy (`SLE`): the cost of a single event happening.
* Finally, we multiply the `SLE` by the number of times we expect it to occur (aka the annualized rate of occurence or `ARO`).
  * The product of SLE x ARO is the annualized loss expectancy (`ALE`).

## Controls

DCISSP defines 7 different types of controls that can all be classified 3 different ways (Administrative, Logical/Technical, and Physical). Several of the 7 types of controls are pretty intuitive to me (e.g. Directive, Preventative, Detective, Recovery); but I do tend to hung-up on the remaining ones:

* A `deterrent` discourages violation of security.
* A `corrective` control minimizes harm done when controls fail. It is distinct from `recovery` insofar as blunting damage done (vs. restoration).
* A `compensating` control is a bit of a cop-out in terms of nomenclature to me: it's a control deployed in conjunction with other controls (like hardware IPS with network IPS). I think that's more confusing than just saying there are multiple X types of controls deployed; case-in-point: the DCISSP example for a compensating physical control is simply "layered defense".
  * EDIT: After practice questions, compensating controls are used when primary controls cannot be implemented and are not a core category in a comprehensive strategy.

## Threat Modeling

This is an area I've been trying to get a better handle on in my day-to-day job as I've been taking on more security architecture responsibilities, but it's still pretty fresh for me in terms of exposure.

I feel reasonably confident with understanding the parts of STRIDE (spoofing, tampering, repudiation, information disclosure, DoS, and elevation of privilege). So I'll focus on drafting PASTA and DREAD (whose acronyms I recall, but not what they stand for or the steps involved).

### PASTA

Short for **Process for Attack Simulation and Threat Analysis**, PASTA is a 7-stage threat modeling method:

1. `Define Objectives`
2. `Define Technical Scope`
3. `Application Decomposition`
4. `Threat Analysis`
5. `Vulnerability and Weakness Analysis`
6. `Attack Modeling`
7. `Risk and Impact Analysis`

### DREAD

A threat modeling method that ranks the severity of threats. Each letter reflects a scorable measure of the threat.

1. `Damage`
2. `Reproducability`
3. `Exploitability`
4. `Affected Users`
5. `Discoverability`

Honestly, I think (2) and (5) have a lot of overlap between them.

## Study log

* `26 May 2026`: 75% on practice questions
  * Was thrown by the number of blockchain-related questions.
  * Got a competing definition of compensating controls
  * Didn't think through the ALE calculation correctly