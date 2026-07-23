# Security Pipeline Report

*Generated 2026-07-18T22:09:36Z — SAST via Brakeman, DAST via OWASP ZAP baseline scan, SCA via Dependabot.*

## Summary

| Severity | Count |
|---|---|
| Critical | 5 |
| High | 13 |
| Medium | 6 |
| Low | 1 |
| **Total** | **25** |

SCA (dependency) vulnerabilities are not duplicated here — Dependabot opens its own PR per vulnerable dependency; see the repo's Dependabot alerts tab.

## Critical / High findings — action required

These need a fix or a documented risk acceptance before merge. Each entry explains the *developer-facing* cause, not just the OWASP/CWE label.

### 1. [Critical] Remote Code Execution — CWE-470: Unsafe Reflection (RCE via dynamic dispatch)

- **Source:** SAST (Brakeman)
- **Where:** `app/controllers/api/v1/mobile_controller.rb:17`
- **What this means for the code:** User input is passed to constantize, send, public_send, or similar reflection methods, letting an attacker instantiate arbitrary classes or call arbitrary methods — often a straight path to remote code execution. Fix: replace dynamic dispatch on user input with an explicit whitelist/case statement mapping allowed values to classes/methods.
- **Scanner detail:** Unsafe reflection method `constantize` called on parameter value

### 2. [Critical] Remote Code Execution — CWE-470: Unsafe Reflection (RCE via dynamic dispatch)

- **Source:** SAST (Brakeman)
- **Where:** `app/controllers/api/v1/mobile_controller.rb:10`
- **What this means for the code:** User input is passed to constantize, send, public_send, or similar reflection methods, letting an attacker instantiate arbitrary classes or call arbitrary methods — often a straight path to remote code execution. Fix: replace dynamic dispatch on user input with an explicit whitelist/case statement mapping allowed values to classes/methods.
- **Scanner detail:** Unsafe reflection method `constantize` called on parameter value

### 3. [Critical] Dangerous Send — CWE-77: Command Injection

- **Source:** SAST (Brakeman)
- **Where:** `app/controllers/dashboard_controller.rb:16`
- **What this means for the code:** User input reaches a command interpreter (shell, system call, or a method that builds one internally). An attacker can inject extra commands or arguments. Fix: don't build commands from user input; if unavoidable, use the array form of system()/Open3 so no shell is invoked, and whitelist the input.
- **Scanner detail:** User controlled method execution

### 4. [Critical] SQL Injection — CWE-89: SQL Injection

- **Source:** SAST (Brakeman)
- **Where:** `app/controllers/users_controller.rb:29`
- **What this means for the code:** A SQL query is built by interpolating user input directly into the query string instead of using bind parameters. Fix: use ActiveRecord parameterized finders (where("x = ?", val)) instead of string interpolation.
- **Scanner detail:** Possible SQL injection

### 5. [Critical] Remote Code Execution — CWE-470: Unsafe Reflection (RCE via dynamic dispatch)

- **Source:** SAST (Brakeman)
- **Where:** `app/controllers/benefit_forms_controller.rb:11`
- **What this means for the code:** User input is passed to constantize, send, public_send, or similar reflection methods, letting an attacker instantiate arbitrary classes or call arbitrary methods — often a straight path to remote code execution. Fix: replace dynamic dispatch on user input with an explicit whitelist/case statement mapping allowed values to classes/methods.
- **Scanner detail:** Unsafe reflection method `constantize` called on parameter value

### 6. [High] Mass Assignment — CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)

- **Source:** SAST (Brakeman)
- **Where:** `app/controllers/users_controller.rb:55`
- **What this means for the code:** A model accepts a hash of attributes from the request and assigns them all, including ones the caller shouldn't be able to set (e.g. admin, role, account_id). Fix: use strong parameters (params.require(...).permit(:only, :allowed, :fields)) and never permit! wholesale.
- **Scanner detail:** Potentially dangerous key allowed for mass assignment

### 7. [High] Cross-Site Scripting — CWE-79: Cross-Site Scripting (XSS)

- **Source:** SAST (Brakeman)
- **Where:** `Gemfile.lock:221`
- **What this means for the code:** User-controlled data is rendered into HTML/JS without escaping (often via html_safe, raw, or unescaped ERB). Fix: let Rails auto-escape by default, and never wrap untrusted data in raw/html_safe.
- **Scanner detail:** rails-html-sanitizer 1.0.3 is vulnerable (CVE-2018-3741). Upgrade to rails-html-sanitizer 1.0.4

### 8. [High] Cross-Site Scripting — CWE-79: Cross-Site Scripting (XSS)

- **Source:** SAST (Brakeman)
- **Where:** `Gemfile.lock:164`
- **What this means for the code:** User-controlled data is rendered into HTML/JS without escaping (often via html_safe, raw, or unescaped ERB). Fix: let Rails auto-escape by default, and never wrap untrusted data in raw/html_safe.
- **Scanner detail:** loofah gem 2.2.0 is vulnerable (CVE-2018-8048). Upgrade to 2.2.1

### 9. [High] Path Traversal — CWE-22: Path Traversal

- **Source:** SAST (Brakeman)
- **Where:** `Gemfile.lock:290`
- **What this means for the code:** A file path is built from user input without stripping '../' or resolving to a safe base directory, so an attacker can read/write files outside the intended folder. Fix: use File.expand_path + a strict prefix check, or a whitelist of allowed filenames.
- **Scanner detail:** sprockets 3.7.1 has a path traversal vulnerability (CVE-2018-3760). Upgrade to sprockets 3.7.2 or newer

### 10. [High] Unmaintained Dependency — CWE-1104: Use of Unmaintained Third-Party Component

- **Source:** SAST (Brakeman)
- **Where:** `Gemfile.lock:206`
- **What this means for the code:** A dependency (or the Ruby/Rails version itself) is past end-of-life and no longer receives security patches. Fix: plan an upgrade — this is the SAST-side signal that lines up with Dependabot's SCA alerts for the same package.
- **Scanner detail:** Support for Rails 5.1.5 ended on 2019-08-25

### 11. [High] Unmaintained Dependency — CWE-1104: Use of Unmaintained Third-Party Component

- **Source:** SAST (Brakeman)
- **Where:** `.ruby-version:1`
- **What this means for the code:** A dependency (or the Ruby/Rails version itself) is past end-of-life and no longer receives security patches. Fix: plan an upgrade — this is the SAST-side signal that lines up with Dependabot's SCA alerts for the same package.
- **Scanner detail:** Support for Ruby 2.5.0 ended on 2021-03-31

### 12. [High] File Access — CWE-22: Path Traversal

- **Source:** SAST (Brakeman)
- **Where:** `app/controllers/benefit_forms_controller.rb:12`
- **What this means for the code:** A file path is built from user input without stripping '../' or resolving to a safe base directory, so an attacker can read/write files outside the intended folder. Fix: use File.expand_path + a strict prefix check, or a whitelist of allowed filenames.
- **Scanner detail:** Parameter value used in file name

### 13. [High] Cross-Site Scripting — CWE-79: Cross-Site Scripting (XSS)

- **Source:** SAST (Brakeman)
- **Where:** `app/views/layouts/application.html.erb:12`
- **What this means for the code:** User-controlled data is rendered into HTML/JS without escaping (often via html_safe, raw, or unescaped ERB). Fix: let Rails auto-escape by default, and never wrap untrusted data in raw/html_safe.
- **Scanner detail:** Unescaped cookie value

### 14. [High] Format Validation — CWE-777: Regular Expression without Anchors

- **Source:** SAST (Brakeman)
- **Where:** `app/models/user.rb:12`
- **What this means for the code:** A validation regex is missing ^/$ anchors (or uses \A/\z incorrectly), so input like "valid-value\nmalicious payload" can slip past the check. Fix: anchor with \A and \z (not ^/$, which match line boundaries in Ruby) for full-string validation.
- **Scanner detail:** Insufficient validation for `email` using `/.+@.+\..+/i`. Use `\A` and `\z` as anchors

### 15. [High] Session Setting — CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag

- **Source:** SAST (Brakeman)
- **Where:** `config/initializers/session_store.rb:4`
- **What this means for the code:** The session cookie can be read by JavaScript, so an XSS bug elsewhere becomes full session theft. Fix: ensure the session store config sets httponly: true (and secure: true over HTTPS).
- **Scanner detail:** Session cookies should be set to HTTP only

### 16. [High] Cross-Site Request Forgery — CWE-352: Cross-Site Request Forgery (CSRF)

- **Source:** SAST (Brakeman)
- **Where:** `app/controllers/application_controller.rb:2`
- **What this means for the code:** A state-changing action can be triggered by a form/request from another origin because CSRF protection is disabled or the token isn't checked. Fix: keep protect_from_forgery enabled and don't skip it for state-changing actions.
- **Scanner detail:** `protect_from_forgery` should be called in `ApplicationController`

### 17. [High] Session Setting — CWE-798: Use of Hard-coded Credentials

- **Source:** SAST (Brakeman)
- **Where:** `config/initializers/secret_token.rb:8`
- **What this means for the code:** A secret key, API token, or password is committed in source rather than pulled from configuration. Fix: rotate the exposed credential and load it from ENV/secrets manager instead.
- **Scanner detail:** Session secret should not be included in version control

### 18. [High] Session Setting — CWE-798: Use of Hard-coded Credentials

- **Source:** SAST (Brakeman)
- **Where:** `config/initializers/secret_token.rb:9`
- **What this means for the code:** A secret key, API token, or password is committed in source rather than pulled from configuration. Fix: rotate the exposed credential and load it from ENV/secrets manager instead.
- **Scanner detail:** Session secret should not be included in version control

<details>
<summary>Medium findings (6) — informational, not blocking</summary>

- **[SAST (Brakeman)]** Remote Code Execution (CWE-502: Deserialization of Untrusted Data) — `app/controllers/password_resets_controller.rb:6`
- **[SAST (Brakeman)]** SQL Injection (CWE-89: SQL Injection) — `app/models/analytics.rb:3`
- **[SAST (Brakeman)]** Cross-Site Scripting (CWE-79: Cross-Site Scripting (XSS)) — `config/environments/production.rb:2`
- **[SAST (Brakeman)]** Mass Assignment (CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)) — `app/controllers/users_controller.rb:50`
- **[SAST (Brakeman)]** Command Injection (CWE-77: Command Injection) — `app/models/benefits.rb:15`
- **[SAST (Brakeman)]** Cross-Site Request Forgery (CWE-352: Cross-Site Request Forgery (CSRF)) — `Gemfile.lock:206`

</details>

<details>
<summary>Low findings (1) — informational, not blocking</summary>

- **[SAST (Brakeman)]** Cross-Site Scripting (CWE-79: Cross-Site Scripting (XSS)) — `Gemfile.lock:221`

</details>

