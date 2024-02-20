---
title: Web Scraping With Python and Selenium
date: 2022-03-09 00:00:00 +/-0000
categories: [general]
tags: [project]     # TAG names should always be lowercase
---

Forenote: the tools and methodologies described below – while legal at the time of publishing this post – violate the terms of service with LinkedIn. Be mindful of running web scraping services on the platform and the potential impacts it may have on your personal social media.

I frequent the /r/cybersecurity subreddit and often see folks new to the InfoSec domain asking what certifications they should pursue in order to get employed in InfoSec; my generic answer has always been to focus on certifications that matter to employers (vs. certifications that matter to the individual). When pressed specifically to name some certifications, my usual suggestion is that they should search job postings and note the certifications that trend in appearance.

Now while the above is well and good for small sample sizes, such an exercise isn’t feasible at scale. The question remains: which certifications do employers want you to get?

## Web Scraping

One such method for figuring this out is leveraging a web scraper. Web scraping essentially extracts data from an array of online sources in an automated fashion for further processing and transformation into useful outputs. While there are certain web scrapers that exist out there right now that can generically extract information from job sites (salary info, employment status, etc), figuring out what certifications these employment listings call for requires a more nuanced approach.

Python, when paired with the Selenium library, offers a means to interact with websites in a browser through code. It affords the programmer the ability to perform any action that someone with a mouse, keyboard and web browser could (but far more quickly and without user interaction). How might this be useful in the development of a web scraper for certifications? A programmer could engineer a script that combs through job listings, notes the presence of certifications, aggregates the results, then spits them back.

## Endpoint Selection

LinkedIn is one of the most used job websites for both individuals looking for work and companies searching for qualified employees. While many of its more nuanced features require a valid account, the platform maintains an endpoint that can be used to publicly search job listings without one here:

```html
https://www.linkedin.com/jobs/search?keywords={parsed.job}&location={parsed.location}&geoId=&trk=public_jobs_jobs-search-bar_search-submit&f_TPR={timeWindow}&f_E={seniority}&position=1&pageNum=0
```

Note how there are numerous points throughout the URL that have various **{parsed.value}** values. With the exception of the **keywords** parameter, these are all optional and can be left blank.

* keywords is the search term passed to LinkedIn, such as “penetration tester” or “cybersecurity analyst”.
* location is the geographic area that we want to restrict the results to.
* f_TPR is the maximum age (in seconds) we want for inclusion in our results.
* f_E is a numbered list (e.g. 1,2,3) from 1-5 inclusive of seniority we want to include in results, with 1 representing internships and 5 being director-level positions.

After setting the above parameters, we can setup a Selenium webdriver which will go to the configured URL. For Firefox, Selenium necessitates the use of Geckodriver for launching the browser (as opposed to a Chromedriver for Chrome).

```python
cyber_url = f'https://www.linkedin.com/jobs/search?keywords={parsed.job}&location={parsed.location}&geoId=&trk=public_jobs_jobs-search-bar_search-submit&f_TPR={timeWindow}&f_E={seniority}&position=1&pageNum=0'

wd = webdriver.Firefox(executable_path='/home/kali/datascrape/geckodriver')

wd.get(cyber_url)
```

When initially searching for jobs, LinkedIn returns the exact number of search results for amounts less than 10,000. Otherwise, it provides rounded whole estimates (e.g. 21,000+). The number of results matters, because the web scraper needs to know how many jobs are shown per page refresh. LinkedIn doesn’t output more than 25 jobs initially; scrolling down to the bottom of the page triggers some dynamic scripting which extends the page to include 25 more results. This continues until eventually the user has to manually click on a “See more jobs” button, which continues this list extension until all jobs are loaded to the page.

## Scoping

The web scraper needs to:

1. Know roughly how many jobs there are, so it can scroll down / click “see more jobs” enough to load a sufficiently large sample size of relevant jobs.
2. Automatically scroll and interact with the page so additional job listings are loaded.

```python
    #Get the overall number of job listings LinkedIn found
    str_of_cyberjobs = str(wd.find_element_by_css_selector('h1>span').get_attribute('innerText'))
    str_of_cyberjobs = str_of_cyberjobs.replace('+','')
    no_cyberjobs = int(str_of_cyberjobs.replace(',', ''))

    #scroll through jobs listings
    jobs_iteration = 0
    if parsed.quick:
        jobs_iteration = 1
    else:
        jobs_iteration = (no_cyberjobs//25)+1
    for i in tqdm(range(jobs_iteration)):
        wd.execute_script('window.scrollTo(0,document.body.scrollHeight);')
        try:
            #Looking for the "See More Jobs" button that eventually appears when scrolling through job listings
            found = len(wd.find_elements(By.CLASS_NAME, 'infinite-scroller__show-more-button--visible'))
            if found > 0:
                wd.find_element(By.CLASS_NAME, 'infinite-scroller__show-more-button--visible').click()
            else:
                time.sleep(1)
                
        except:
            time.sleep(1)
            pass
            
    #Find all jobs
    job_list = wd.find_element(By.CLASS_NAME, 'jobs-search__results-list')
    #Look at each job
    jobs = job_list.find_elements(By.TAG_NAME, 'li')
    print(f'The number of jobs actually to be processed: {len(jobs)}')
```
There’s a lot more happening here, but essentially the above code is doing exactly what we outlined above. The first chunk retrieves LinkedIn’s number of results for us to work with. The next block sets up a for-loop to keep scrolling/clicking; there’s quality of life additions such as the tqdm wrapper for a CLI loading/progress bar. Finally, we denote the actual number of jobs the web scraper will iterate over (since there can be some latency errors in interacting with the browser, which causes some clicks/scrolls to not register. This is okay, since the end goal of the web scraper is to observe a trend (and losing some of the job listings, especially later ones which are only tenuously related to the keywords or are very old, is alright).

## Collection

Unfortunately, LinkedIn doesn’t include relevant certifications in the short panel of the job listings (just the name of the position, company, and some other ancillary info). In order for the scraper to see certifications, it needs to click on each job listing in order to view the full job description. The next steps then are:

* Iterate over all job listings
* For each job listing, wait long enough to ensure that the browser actually loads the content before processing/moving on to the next listing

```python
    job_num = 1
    
    #Enumerating jobs
    for job in tqdm(jobs):
        #Pulling information from the job description by clicking through each job
        #Reference for fetching XPATH: https://www.guru99.com/xpath-selenium.html
        job_link = f"/html/body/div[1]/div/main/section[2]/ul/li[{job_num}]/*"
        try:
            wd.find_element(By.XPATH, job_link).click()
        except:
            job_num += 1
            continue
        #The first several jobs are particularly relevant to the -j flag
        #Subsequent results are less important and don't need as much attention
        if job_num < 50:
            try:
                WebDriverWait(wd, parsed.increment).until(EC.element_to_be_clickable((By.XPATH, "/html/body/div[1]/div/section/div[2]/section/div/div[1]/div/div/a")))
            except:
                job_num += 1
                continue
            
        else:
            if parsed.quick:
                break
            try:
                WebDriverWait(wd, parsed.increment).until(EC.element_to_be_clickable((By.XPATH, "/html/body/div[1]/div/section/div[2]/section/div/div[1]/div/div/a")))
            except:
                job_num += 1
                continue
```

The above code iterates over every listing and leverages Selenium’s Explicit Wait functionality in order to await page loads. The Explicit Wait (imported as EC in the code above), waits for a specific number of seconds (variable parsed.increment) for the full job description to load. It either identifies that the content has loaded or determines that it’s taking too long to load the page and moves along. This particular code also includes some functionality with parsed.quick, which allows the user to specify if they only want to scrape the first 50 results (vs. hundreds, thousands, or tens of thousands).

## Scraping

At this point, the web scraper needs to key in on certifications that appear in the job’s full description. This is still problematic however, since there is no standardization for how recruiters/employers list certification requirements. There are a few trends to observe, however:

* Generally, certifications are listed when the listing includes keywords such as “certification”, “certs”, or “accreditations”.
* Wherever the above keywords appear, the listed certifications generally appear in the same line, if not in elements immediately following.
* Certifications generally are listed as abbreviations (e.g. “Offensive Security Certified Professional” = “OSCP”). Occasionally they include either dashes “-” or other symbols (such as ending with a “+”).

Here’s a way we can implement to these rules:

```python
        keywords = ["certification", "certifications", "certs", "Certification", "Certifications", "Certs", "accreditations", "accreditation"]
        jd_certs = set()
        
        #Check if any of the of the keywords appear in the job description
        for keyword in keywords:
            key = f"//*[contains(text(), '{keyword}')]"
            found = len(wd.find_elements(By.XPATH, key))
            
            #If a keyword is found, scrutinize
            if found > 0:
                #Parse lines that have the keywords for certifications
                #Parse the line that has the keyword first
                try:
                    jd_foundline = wd.find_element(By.XPATH, key)
                except:
                    break
                jd_foundlines = wd.find_elements(By.XPATH, key)
                for jd_foundline in jd_foundlines:
                    sentence = jd_foundline.get_attribute('innerHTML')
                    
                    #Use regex to identify
                        #Certs that may include a "-"
                        #Certs that end with a "+"
                        #Certs that include at least 2 consecutive uppercase characters
                    cert_check = re.findall('[A-Z]+\-+[\w]+|[a-zA-Z]+\+|[\w]+[A-Z]{2,}', sentence)
                    
                    #Add found certifications to the set of discovered certs in the job listing
                    if len(cert_check) > 0:
                        #print(IGreen + "[+] Found these certs:")
                        #print(cert_check)
                        jd_certs.update(cert_check)
                    else:
                        all_children_by_xpath = jd_foundline.find_elements_by_xpath(".//*")
                        
                        #Check if any children elements exist that may have certs
                        for child in all_children_by_xpath:
                            sentence = child.get_attribute('innerHTML')
                            cert_check = re.findall('[A-Z]+\-+[\w]+|[a-zA-Z]+\+|[\w]+[A-Z]{2,}', sentence)
                            if len(cert_check) > 0:
                                jd_certs.update(cert_check)
                            else:
                                pass
                                
                        tags = ["p", "li", "ul"]
                        
                        for tag in tags:
                            another_el = []
                            next_el = jd_foundline.find_elements(By.XPATH, f".//following-sibling::{tag}")
                            if len(next_el) > 0:
                                sentence = next_el[0].get_attribute('innerHTML')
                                #print(IWhite + sentence)
                                cert_check = re.findall('[A-Z]+\-+[\w]+|[a-zA-Z]+\+|[\w]+[A-Z]{2,}', sentence)
                                if len(cert_check) > 0:
                                    jd_certs.update(cert_check)
                                    another_el = next_el[0].find_elements(By.XPATH, f".//following-sibling::{tag}")
                                    
                            #This loop only triggers if we found a single valid cert
                            #Cycle through subsequent sibling elements of the same type to find more certifications
                            while True:    
                                    if len(another_el) > 0:
                                        sentence = another_el[0].get_attribute('innerHTML')
                                        cert_check = re.findall('[A-Z]+\-+[\w]+|[a-zA-Z]+\+|[\w]+[A-Z]{2,}', sentence)
                                        if len(cert_check) > 0:
                                            jd_certs.update(cert_check)
                                            #Try grabbing the next element
                                            another_el = another_el[0].find_elements(By.XPATH, f".//following-sibling::{tag}")
                                        #The sibling element didn't have a recognized cert
                                        else:
                                            break
                                    #The next element is absent
                                    else:
                                        break
```

Again, the above code may seem complicated, but essentially the following is happening:

1. We check for the presence of the various keywords in the job description.
2. If we find a keyword, examine the same web element to see if certifications are present (via regex-matching rules).
3. If none are found, we first check to see if any child web elements exist (such as nested li elements) and if they have certifications; we then check the sibling elements if some exist.
4. If any are found, we keep checking sibling elements until the regex-matching rules fail.

The code ends with formatting/outputting the results.

> Update (November 2023): I went back and performed some updates on the script when updating my "[What Cybersecurity Certifications Should You Get?]( {% post_url 2023/2023-11-08-what-certifications-should-you-get %} )" post. In my first draft of this script, I was missing a lot of job openings due to timeouts waiting for the browser to render DOM elements. Instead, I found an alternative endpoint that I could submit GET requests to and search over the response text much faster. This has dramatically improved speed and sampling.
{: .prompt-info }

## Example Tooling

I built a tool that implements all of the above as a proof-of-concept. It has some added functionality that allows the user to specify various parameters, iteration speed control, and accommodating various interrupts/exceptions that may occur.

You can test the tool yourself by forking [my repository off of GitHub](https://github.com/ahessmat/LinkedInfoSec).

You can also see the results of some of the data I’ve processed here.