# 0xbr484 — site

> infosec · bug bounty · offensive research — https://br484.github.io/

Personal offensive-security site, built with **Jekyll** and a custom
**terminal/CRT** theme (muted phosphor green, monospace, dark). No JavaScript,
no third-party fonts/CDNs, no trackers.

## Run locally

```bash
bundle install
bundle exec jekyll serve --port 4123
# http://127.0.0.1:4000
```

## Write a post

Create `_posts/YYYY-MM-DD-title.md`:

```markdown
---
title: "CVE-2026-XXXX — RCE in Product Y"
date: 2026-06-23 12:00:00
categories: [cve]
tags: [rce, disclosure]
---

Markdown content...
```

Add `archived: true` to the front matter to move an old post into the
dimmed `./archive` section.

Deploy is automatic: every push to `main` runs the GitHub Action
(`.github/workflows/jekyll.yml`), which builds and publishes the `gh-pages` branch.

## Layout

```
_layouts/    default · home · post · page
_includes/   head · header · footer · post-item
assets/css/  style.scss  (terminal theme)
_posts/      posts in markdown
```
