---
layout: post
title: "wp2shell — WordPress core pre-auth SQLi, shell-flavored (CVE-2026-63030 + CVE-2026-60137)"
date: 2026-07-18 14:00:00
categories: research
---

Two patched WordPress core bugs chain into an **unauthenticated SQL injection**. Shell is on the table too — but conditional: a SQLi with a **taste** of shell, not a guaranteed one. No plugin bug for the SQLi, no credentials for either. Reconstructed from the public patch, validated in a lab.

**Affected:** `6.9.0–6.9.4` / `7.0.0–7.0.1`. **Fixed:** `6.9.5` / `7.0.2` / `6.8.6`.

<!--more-->

## The bug

- **CVE-2026-60137 (SQLi).** `WP_Query`'s `author__not_in` is only `absint()`-sanitized when it's an *array*. A *string* flows raw into `AND wp_posts.post_author NOT IN (<attacker>)`. REST maps `author_exclude` → `author__not_in`, but the schema coerces it to an int array, so a raw string is normally rejected `400`.
- **CVE-2026-63030 (batch route confusion).** In `serve_batch_request_v1()`, a sub-request that fails to parse is pushed to `$validation[]` but **not** `$matches[]` (the fix adds the missing `$matches[]`). The arrays misalign → request *i* runs under **another** request's handler: validate-as-A, execute-as-B.

Chained, two nested batches smuggle a `GET` (carrying the raw `author_exclude`) into the posts `get_items` reader, pre-auth:

```text
POST /wp-json/batch/v1  (validation:normal)
├─ [0] "//a:b"                         → WP_Error (misaligns OUTER)
├─ [1] POST /wp/v2/posts  body=INNER   → validated as create_item, executed as /batch/v1 → runs INNER
│      ├─ [0] "//a:b"                   → WP_Error (misaligns INNER)
│      ├─ [1] GET /wp/v2/categories?author_exclude=<SQLi>
│      │                                → validated as categories (raw string survives),
│      │                                  executed as posts get_items → author__not_in → SQLi
│      └─ [2] GET /wp/v2/posts
└─ [2] POST /batch/v1 {requests:[POST /wp/v2/posts]}
```

## Impact

- **SQLi — universal.** Any unpatched target in range, zero plugins. Unauth dump of `wp_users` (login + `$wp$` bcrypt hash), `wp_options`, any table. The oracle is a boolean (`OR 1=1` → all posts, `OR 1=2` → fewer), so it's jitter-immune.
- **RCE — the flavor.** Unauth, but conditional on two patterns that are common on real sites yet not default: (1) a plugin/theme that drops REST pagination (`nopaging`) → forces `split_the_query=false` → a `UNION` returns a fully attacker-controlled row → rendered `post_content`; (2) a shortcode that unserializes attacker input next to a POP gadget. On a bare stock install it **doesn't** reach RCE — every core gadget is `__wakeup`-guarded and `split=false` can't be forced pre-auth. So: always a critical SQLi, sometimes a shell.

## Tooling

- **Exploit** — [`wp2shell.py`](/assets/wp2shell/wp2shell.py) · `check` (safe boolean/time detection) / `read` (blind dump, `--sql`) / `rce` (`--cmd`). Python 3, no deps.
- **Nuclei template** — [`wp2shell.yaml`](/assets/wp2shell/wp2shell.yaml) · safe single-fire `SLEEP` probe (reads/writes nothing). Field note: patched cores return `500` on the nested batch instead of the `"responses"` structure — a clean patched-vs-vulnerable tell.
- **Lab** — [`cachekit-lab.php`](/assets/wp2shell/cachekit-lab.php) · mu-plugin supplying the two RCE preconditions on a `7.0.1` lab (pin the version + `define('AUTOMATIC_UPDATER_DISABLED', true);`, or it self-updates to `7.0.2`).

```
python3 wp2shell.py check http://target
python3 wp2shell.py read  http://target
python3 wp2shell.py rce   http://target --cmd "id; uname -a"
```

## Fix

Update to **7.0.2 / 6.9.5 / 6.8.6**. Interim WAF: block `POST /wp-json/batch/v1` and `?rest_route=/batch/v1` for anonymous users.

---

Original disclosure by Searchlight Cyber; reconstructed independently from the patch. For authorized testing only. — br484
