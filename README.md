# Spinning up local instance of project site
Making a note of this so others don't need to look up the steps to spin it up anymore.

```
apt install ruby-bundler
apt install build-essential ruby-dev libffi-dev libssl-dev zlib1g-dev
bundle install
bundle exec jekyll serve --force_polling
```

# TODO
* Posts
  * D&D app
  * Blog on DNS records
  * HTB Tier 3 Content
  * CWEE
  * Web Cache Vuln Demo
  * HTB machine submission
  * [Common mistakes](https://old.reddit.com/r/cybersecurity/comments/1kkf01d/mentorship_monday_post_all_career_education_and/ms5qgp1/)

# Organizational notes for self

* The Chirpy Starter splits content between the root project directory and the corresponding gem (jekyll-theme-chirpy*).
  * Content/folders placed into the root directory override what's in the theme.
* The assets directory contains:
  * images: which hosts images accessible site-wide
  * img: which hosts the requisite favicon information
* The _includes directory was updated to include footer.html so as to override the Jekyll default footer.
* The _layouts directory was copied from the gem theme and altered to include Google Analytics code.
  * Chirpy's default configuration was designed for UA, which became deprecated in July 2023
* Went through and updated instances of http:// to https:// to mitigate mixed-content errors.

# Chirpy Starter

[![Gem Version](https://img.shields.io/gem/v/jekyll-theme-chirpy)][gem]&nbsp;
[![GitHub license](https://img.shields.io/github/license/cotes2020/chirpy-starter.svg?color=blue)][mit]

When installing the [**Chirpy**][chirpy] theme through [RubyGems.org][gem], Jekyll can only read files in the folders
`_data`, `_layouts`, `_includes`, `_sass` and `assets`, as well as a small part of options of the `_config.yml` file
from the theme's gem. If you have ever installed this theme gem, you can use the command
`bundle info --path jekyll-theme-chirpy` to locate these files.

The Jekyll team claims that this is to leave the ball in the user’s court, but this also results in users not being
able to enjoy the out-of-the-box experience when using feature-rich themes.

To fully use all the features of **Chirpy**, you need to copy the other critical files from the theme's gem to your
Jekyll site. The following is a list of targets:

```shell
.
├── _config.yml
├── _plugins
├── _tabs
└── index.html
```

To save you time, and also in case you lose some files while copying, we extract those files/configurations of the
latest version of the **Chirpy** theme and the [CD][CD] workflow to here, so that you can start writing in minutes.

## Prerequisites

Follow the instructions in the [Jekyll Docs](https://jekyllrb.com/docs/installation/) to complete the installation of
the basic environment. [Git](https://git-scm.com/) also needs to be installed.

## Installation

Sign in to GitHub and [**use this template**][use-template] to generate a brand new repository and name it
`USERNAME.github.io`, where `USERNAME` represents your GitHub username.

Then clone it to your local machine and run:

```console
$ bundle
```

## Usage

Please see the [theme's docs](https://github.com/cotes2020/jekyll-theme-chirpy#documentation).

sudo apt update && sudo apt upgrade -y
sudo apt install ruby-full build-essential zlib1g-dev -y
sudo bundle install
bundle exec jekyll serve

## License

This work is published under [MIT][mit] License.

[gem]: https://rubygems.org/gems/jekyll-theme-chirpy
[chirpy]: https://github.com/cotes2020/jekyll-theme-chirpy/
[use-template]: https://github.com/cotes2020/chirpy-starter/generate
[CD]: https://en.wikipedia.org/wiki/Continuous_deployment
[mit]: https://github.com/cotes2020/chirpy-starter/blob/master/LICENSE
