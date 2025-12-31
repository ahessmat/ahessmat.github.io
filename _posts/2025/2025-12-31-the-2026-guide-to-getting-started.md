---
title: Getting Started in Cybersecurity
date: 2025-12-30 00:00:00 +/-0000
categories: [career guidance]
tags: [popular]     # TAG names should always be lowercase
published: false
image:
    path: /assets/images/2025/htb-ctf-banner.png
---

## The 2026 Guide to Getting Started in Cybersecurity

Welcome — this is a short interactive proof-of-concept to help you pick a starting path in cybersecurity. Select who you are from the menu below and this post will show a tailored starter plan.

<section id="cyberstarter" class="cyberstarter">
  <label for="persona"><strong>Who are you?</strong></label>
  <select id="persona" aria-label="Select who you are">
    <option value="">— Choose your role —</option>
    <option value="student">University student</option>
    <option value="career">Career-changer</option>
    <option value="tech">Employed in tech</option>
    <option value="highschool">High schooler</option>
    <option value="hobbyist">Curious hobbyist</option>
  </select>
  <button id="reset" type="button">Reset</button>
</section>

<!-- persona sources rendered to HTML (hidden) via include_relative -->
<div id="persona-sources" style="display:none">
  <div data-key="student">
    {% capture student %}{% include_relative 2026-guide-support/student.md %}{% endcapture %}{{ student | markdownify }}
  </div>
  <div data-key="career">
    {% capture career %}{% include_relative 2026-guide-support/career.md %}{% endcapture %}{{ career | markdownify }}
  </div>
  <div data-key="tech">
    {% capture tech %}{% include_relative 2026-guide-support/tech.md %}{% endcapture %}{{ tech | markdownify }}
  </div>
  <div data-key="highschool">
    {% capture highschool %}{% include_relative 2026-guide-support/highschool.md %}{% endcapture %}{{ highschool | markdownify }}
  </div>
  <div data-key="hobbyist">
    {% capture hobbyist %}{% include_relative 2026-guide-support/hobbyist.md %}{% endcapture %}{{ hobbyist | markdownify }}
  </div>
</div>

<div id="persona-content" class="cyber-content">
  <p class="muted">Select an option above to see a tailored starter path:</p>
</div> 

<style>
/* basic styles for the POC */
.cyberstarter { margin: 1rem 0; display:flex; gap:0.5rem; align-items:center; }
.cyber-content { border-left: 3px solid #2b6cb0; padding: 1rem; background:#f8fafc; margin-top:1rem; }
.cyber-content h3 { margin-top:0; }
.muted { color:#6b7280; }
</style>

<script>
// Load persona content from server-rendered hidden includes
document.addEventListener('DOMContentLoaded', function(){
  // Collect persona HTML from hidden includes rendered by Jekyll
  const source = document.getElementById('persona-sources');
  const contentMap = {};
  if(source){
    source.querySelectorAll('[data-key]').forEach(div => {
      const key = div.getAttribute('data-key');
      contentMap[key] = div.innerHTML.trim();
    });
  }

  const select = document.getElementById('persona');
  const content = document.getElementById('persona-content');
  const resetBtn = document.getElementById('reset');

  function render(value){
    if(!value){
      content.innerHTML = '<p class="muted">Select an option above to see a tailored starter path.</p>';
      return;
    }
    content.innerHTML = contentMap[value] || '<p>Content not available yet.</p>';
    content.scrollIntoView({behavior:'smooth'});
  }

  select.addEventListener('change', (e) => render(e.target.value));
  resetBtn.addEventListener('click', function(){ select.value=''; render(''); select.focus(); });

  // Preselect from URL param like ?persona=student for quick preview
  const params = new URLSearchParams(window.location.search);
  const p = params.get('persona');
  if(p && contentMap[p]){ select.value = p; render(p); }
});
</script>

