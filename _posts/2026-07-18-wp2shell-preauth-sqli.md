---
layout: post
title: "wp2shell — WordPress core pre-auth SQLi, shell-flavored (CVE-2026-63030 + CVE-2026-60137)"
date: 2026-07-18 00:30:00 -0300
categories: research
---

Two patched WordPress core bugs chain into an **unauthenticated SQL injection**. Shell is on the table too — but conditional: a SQLi with a **taste** of shell, not a guaranteed one. No plugin bug for the SQLi, no credentials for either. Reconstructed independently from the public patch, validated end-to-end in an isolated lab.

**Affected:** `6.9.0–6.9.4` / `7.0.0–7.0.1`. **Fixed:** `6.9.5` / `7.0.2` / `6.8.6`.

<!--more-->

## TL;DR — two capabilities, different reach

| Capability | Auth | Works on a stock install (no plugins)? | Severity |
|---|---|---|---|
| **Blind SQL injection** — dump `wp_users` (login + hash), `wp_options`, any table | none | **Yes — always, universal** | Critical |
| **Remote code execution** — object injection → shell | none | **No** on pure stock; **yes** when the site has two common plugin patterns | Critical (conditional) |

The SQLi is universal — any unpatched target in the version range, zero plugins. The RCE is conditional — it fires on real sites that meet two preconditions (below), common but not default. On a bare stock install we proved the RCE does *not* close, and exactly why.

---

## The two bugs

**CVE-2026-60137 — SQL injection (CWE-89).** In `WP_Query`, `author__not_in` is only sanitized with `absint()` when it arrives as an **array**. Pass it a **string** and it flows raw into the query:

```sql
AND wp_posts.post_author NOT IN (<attacker string>)
```

The REST posts endpoint maps `author_exclude` → `author__not_in`, so `GET /wp/v2/posts?author_exclude=...` reaches it. On its own this is dormant: the REST schema coerces `author_exclude` to an int array, so a raw string is rejected with `400`. It needs a delivery that gets a raw string past the schema.

**CVE-2026-63030 — REST batch route confusion (CWE-436).** That delivery. In `WP_REST_Server::serve_batch_request_v1()`, when a sub-request fails to parse (`wp_parse_url` returns false), the vulnerable build pushes to `$validation[]` but **not** to `$matches[]`:

```php
if ( is_wp_error( $single_request ) ) {
    $has_error    = true;
    // 7.0.2 adds: $matches[] = $single_request;   <-- the fix
    $validation[] = $single_request;
    continue;
}
```

The two arrays now **misalign by index**. With `"validation":"normal"` (which skips the require-all-validate early return), execution does `respond_to_request($requests[$i], …, $matches[$i])` — running request *i* under **another** request's handler. Validate-against-handler-A, execute-handler-B.

---

## Delivery chain — how the raw string reaches the sink, pre-auth

The batch method enum only allows `POST/PUT/PATCH/DELETE`, so a `GET` (needed to hit the public `get_items` reader) can't be sent directly. Two **nested** batches solve both walls at once — the method allowlist and the schema coercion:

```text
POST /wp-json/batch/v1   (validation:normal)
├─ [0] path "//a:b"                         → WP_Error (misaligns OUTER)
├─ [1] POST /wp/v2/posts  body = INNER      → validated as create_item (no 'requests' in schema, so the
│                                             method enum is NOT checked) but EXECUTED as the /batch/v1
│                                             handler → runs INNER, smuggling the GET sub-requests
│       INNER (validation:normal):
│       ├─ [0] path "//a:b"                  → WP_Error (misaligns INNER)
│       ├─ [1] GET /wp/v2/categories?author_exclude=<SQLi>
│       │                                    → validated as `categories` (route allows batch and has NO
│       │                                      author_exclude in its schema → the raw string survives),
│       │                                      but EXECUTED as posts `get_items` → raw author_exclude →
│       │                                      author__not_in → SQL INJECTION
│       └─ [2] GET /wp/v2/posts             → puts posts get_items into matches[1]
└─ [2] POST /batch/v1  {requests:[POST /wp/v2/posts]}  → puts the batch handler into outer matches[1]
```

Lax routes that work for the injected sub-request (batch-allowed **and** with no `author_exclude` in schema): `categories`, `tags`, `users`, `blocks`.

---

## Impact that is always available: blind SQLi

The injected `WHERE` executes regardless of anything else, so boolean/time-based extraction is universal. The oracle is clean: a true condition (`… OR 1=1`) makes `get_items` return **all** posts; a false one (`… OR 1=2`) returns fewer → the row count *is* the boolean. No timing dependency, so it's immune to network jitter.

Dumping the admin bcrypt hash (`$wp$` = WP 6.8+ bcrypt over `base64(hmac_sha384("wp-sha384", pw))`), `wp_options`, and arbitrary tables is a Critical unauthenticated finding on its own — before any talk of RCE.

---

## From read-only SQLi to full-row control

To go past blind read you need `WP_Query` to return **attacker-controlled rows** via `UNION`. That requires `split_the_query === false`:

```php
$split_the_query = $is_unfiltered_query && (
    wp_using_ext_object_cache() || ( ! empty($limits) && $query_vars['posts_per_page'] < 500 ) );
```

- `split = true` → WP selects IDs, then re-fetches rows by ID → `UNION`-injected columns are discarded.
- `split = false` → a single `SELECT wp_posts.* …` → a `UNION SELECT` returns a **fully controlled** `wp_posts` row that becomes a `WP_Post`.

To force `split = false` you need `$limits` empty (nopaging) **and** no persistent object cache. Removing the LIMIT also drops `SQL_CALC_FOUND_ROWS`, which otherwise makes `UNION` a syntax error. **This is exactly the advisory's "no persistent object cache" precondition** — but on stock it's unreachable (REST caps `per_page` at 100, and nothing maps a param to `nopaging`). A plugin or theme that sets `nopaging`/`orderby` on REST post queries (very common) unlocks it.

With full-row control the attacker controls `post_content`, and REST renders it:
`content['rendered'] = apply_filters('the_content', $post->post_content)` → `do_blocks` + `do_shortcode`.

---

## From full-row control to code execution

Attacker `post_content` → `do_shortcode` → a plugin shortcode that unserializes attacker input → a POP gadget:

```text
[cachekit]<hex(serialized gadget)>[/cachekit]
  → maybe_unserialize(...)
  → CacheKit_Deferred::__destruct()  →  call_user_func("system", "<cmd>")
```

Payload notes for reproduction: 23 `wp_posts.*` columns; empty strings via `TRIM(0x20)` (a literal `''` is stripped on the param path); values via `0x..` hex; `post_status=publish` and empty `post_password` so the row renders; the shortcode reads **hex** so it survives `wptexturize`.

### Preconditions for the RCE (be honest)

Both are common on real sites, neither is default:

1. **A plugin/theme that removes REST pagination** (`nopaging`/`orderby` via `pre_get_posts` / `rest_post_query`). Unlocks `split=false` + kills `SQL_CALC_FOUND_ROWS` → full-row `UNION` control.
2. **A plugin that unserializes attacker-controllable content and ships a POP gadget** (Monolog/Guzzle/Laminas-class — near-universal in plugin `vendor/` dirs). The gadget is the terminal; the unserialize-of-rendered-content is the sink.

wp2shell's value: it turns an object-injection sink that would normally need auth into **pre-auth RCE**, because the SQLi lets you inject rendered content anonymously.

---

## Why a bare stock install does *not* reach RCE

No public writeup has this part. On stock `7.0.1` the RCE reduces to a **delivery problem**, closed by two independent walls — each verified, not assumed:

**Wall A — no full-row control.** `UNION` control needs `split_the_query === false`, which needs an empty `LIMIT` (nopaging). Pre-auth on stock this is unreachable: `per_page` is capped at 100 (rejected, not clamped), nothing maps a REST param to `nopaging`/`posts_per_page`/`fields`, and there is no core `posts_request` filter. Core *does* run nopaging queries (`revisions`, `global-styles/revisions` with `posts_per_page => -1`) but they are auth-gated (`edit_post` on the parent) and don't read the `author_exclude` sink.

**Wall B — no live terminal gadget, and no path to `unserialize` with attacker bytes.**

- We **empirically killed** the object-injection terminal. `WP_HTML_Token::__destruct` is a perfect single-hop gadget — `call_user_func($this->on_destroy, $this->bookmark_name)`, both public properties — but its `__wakeup()` throws. We tested **9 bypass shapes** (top-level, in-array, stdClass property, reference `r:2`, object+trailing data, property-count mismatch +1/+3, trailing junk, mid-bad) across **PHP 7.4.33, 8.1.34 and 8.3.32** — all dead. WP 7.0.1 requires PHP ≥ 7.4, so no PHP that runs a vulnerable target ships a live core gadget. Every other core gadget class is `__wakeup`-guarded (`WP_Theme`, `Requests\*`, HTML-API) or has a non-gadget destructor (PHPMailer=`smtpClose`, SimplePie=`unset`).
- The SQLi is **read-only** (no stacked queries; `SQL_CALC_FOUND_ROWS` breaks `UNION` whenever a LIMIT exists) and the DB user has no `FILE` privilege → can't write a webshell, read `wp-config` salts, or plant serialized bytes.
- No unauthenticated endpoint stores an attacker string into meta/options that `maybe_unserialize` would later revive (the second-order object-injection pattern needs a plugin write).

**Conclusion:** on a bare stock `7.0.1` with a supported PHP, the pre-auth SQLi **cannot** be escalated to RCE by any source-derivable path. A *proven negative*, not a gap we skipped. It also implies the "no plugins" RCE narrative most plausibly describes the **SQLi delivery** (genuinely no-plugins) unless a primitive outside the source-derivable surface is being held back.

The enablers that *do* open RCE — all common on real sites, none default:

| Enabler | What it unlocks |
|---|---|
| Plugin/theme sets `nopaging`/`orderby` on REST post queries | Wall A → full-row `UNION` → rendered attacker `post_content` |
| Plugin unserializes attacker content + ships a POP gadget | Wall B → object injection → RCE (demonstrated) |
| Plugin with an anon-writable serialized meta field | Second-order object injection (Wall B), independent of full-row |
| Empty/undefined salts in `wp-config.php` (misconfig) | SQLi reads DB salts → forge admin cookie → theme/plugin editor → RCE (plugin-free) |

---

## Tooling

- **Exploit** — [`wp2shell.py`](/assets/wp2shell/wp2shell.py) · `check` (safe boolean/time detection) / `read` (blind dump, `--sql`) / `rce` (`--cmd`). Python 3, no deps.
- **Nuclei template** — [`wp2shell.yaml`](/assets/wp2shell/wp2shell.yaml) · safe single-fire `SLEEP` probe (reads/writes nothing). Field note: patched cores return `500` on the nested batch instead of the `"responses"` structure — a clean patched-vs-vulnerable tell.
- **Lab** — [`cachekit-lab.php`](/assets/wp2shell/cachekit-lab.php) · mu-plugin supplying the two RCE preconditions on a `7.0.1` lab (pin the version + `define('AUTOMATIC_UPDATER_DISABLED', true);`, or it self-updates to `7.0.2`).

```
python3 wp2shell.py check http://target
python3 wp2shell.py read  http://target
python3 wp2shell.py read  http://target --sql "SELECT @@version"
python3 wp2shell.py rce   http://target --cmd "id; uname -a"
```

---

## Fix

Update to **7.0.2 / 6.9.5 / 6.8.6**. Interim WAF: block `POST /wp-json/batch/v1` and `?rest_route=/batch/v1` for anonymous users. Note: WordPress auto-updates security releases by default — a lab pinned to `7.0.1` silently patches itself to `7.0.2`; disable with `AUTOMATIC_UPDATER_DISABLED` when testing.

---

Original disclosure by Searchlight Cyber; reconstructed independently from the patch. For authorized testing only. — br484
