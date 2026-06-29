# WebGoat Security Scan Report

**Date:** 2026-06-29
**Branch:** `main`
**Tools Used:**
- SonarQube Cloud (SonarCloud) -- full SAST analysis
- Semgrep OSS 1.168.0 -- static analysis with default `auto` rulesets
- OWASP Dependency-Check Maven profile (`-Powasp`) -- attempted; NVD database
download could not complete in reasonable time without an NVD API key.
Dependency CVE analysis below is based on manual review of `pom.xml` versions
and known public advisories.

> **Important context:** WebGoat is a *deliberately insecure* OWASP teaching
> application. The majority of findings below are **intentional lesson content**.
> Each finding is tagged accordingly.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Dependency CVEs](#2-dependency-cves)
3. [Code-Level Findings -- SAST](#3-code-level-findings----sast)
   - [3a. SonarQube Vulnerabilities (42)](#3a-sonarqube-vulnerabilities-42)
   - [3b. SonarQube Security Hotspots (13)](#3b-sonarqube-security-hotspots-13)
   - [3c. Semgrep Findings (53)](#3c-semgrep-findings-53)
4. [Genuine / Accidental Issues](#4-genuine--accidental-issues)
5. [Recommendations](#5-recommendations)

---

## 1. Executive Summary

|              Metric               |                           Value                            |
|-----------------------------------|------------------------------------------------------------|
| SonarQube Quality Gate            | **PASSED** (new code)                                      |
| Security Rating                   | E (5.0 -- worst; expected for a deliberately insecure app) |
| Total SonarQube Vulnerabilities   | 42                                                         |
| Total SonarQube Security Hotspots | 13                                                         |
| Total Semgrep Findings            | 53                                                         |
| Known Vulnerable Dependencies     | 3 (intentional) + 1 (legacy)                               |
| **Likely Genuine Issues**         | **~6** (see [Section 4](#4-genuine--accidental-issues))    |

---

## 2. Dependency CVEs

The OWASP Dependency-Check Maven profile was started (`mvn verify -Powasp`) but
the NVD database download requires an NVD API key to complete in reasonable time
(361,577 records). The `pom.xml` configures `failBuildOnCVSS >= 7` with
suppressions in `config/dependency-check/project-suppression.xml`.

### 2a. Intentionally Vulnerable Dependencies

These libraries are pinned at old versions **on purpose** for lesson content.
The `pom.xml` marks them with `<!-- do not update necessary for lesson -->`.

|               Library                | Version |                                                                              Known CVEs (CVSS >= 7)                                                                              |                      Used By Lesson                      |
|--------------------------------------|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| **com.thoughtworks.xstream:xstream** | 1.4.5   | CVE-2013-7285 (RCE, 9.8), CVE-2020-26217 (RCE, 9.8), CVE-2021-21344 through CVE-2021-21351 (multiple RCE, 9.8), CVE-2021-43859 (DoS, 7.5), CVE-2022-41966 (DoS, 7.5) + many more | `vulnerablecomponents` -- XStream deserialization lesson |
| **cglib:cglib-nodep**                | 3.3.0   | CVE-2019-14379 (when used with Jackson -- context-dependent)                                                                                                                     | Reflection/proxy lesson support                          |
| **io.jsonwebtoken:jjwt**             | 0.9.1   | CVE-2022-21449 (via ECDSA, Java-level), general EOL status; no direct high-CVSS CVE but pre-1.0 API has known weaknesses in key handling                                         | `jwt` -- JWT manipulation lessons                        |

> **Suppression file** (`config/dependency-check/project-suppression.xml`)
> already suppresses the XStream CVEs listed above, confirming they are known
> and intentional.

### 2b. Legacy / Potentially Outdated Dependencies

|           Library           | Version |                                                                                        Notes                                                                                        |
|-----------------------------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **javax.xml.bind:jaxb-api** | 2.3.1   | Legacy Java EE API; superseded by `jakarta.xml.bind`. No high-severity CVE, but it is an unmaintained dependency. The project already includes `jakarta.xml.bind-api` alongside it. |

### 2c. Up-to-Date Dependencies (No Known High CVEs)

The bulk of the dependency tree is managed by Spring Boot 4.1.0 BOM and is
current:

- Spring Framework 7.0.8, Spring Boot 4.1.0
- Jackson 2.21.4 / 3.1.4
- Flyway 12.4.0
- Hibernate ORM 7.4.1
- Tomcat Embed 11.0.22
- Logback 1.5.34, SLF4J 2.0.18
- SnakeYAML 2.6

---

## 3. Code-Level Findings -- SAST

### 3a. SonarQube Vulnerabilities (42)

#### By Severity

| Severity | Count |
|----------|-------|
| BLOCKER  | 2     |
| CRITICAL | 2     |
| MAJOR    | 31    |
| MINOR    | 7     |

#### By Rule

|         Rule         | Count |            Description             |                                                                   Intentional?                                                                   |
|----------------------|-------|------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| **java:S2068**       | 15    | Hard-coded passwords               | Yes -- lesson content for `securitymisconfiguration`, `challenges`, `idor`, `insecurelogin`, `jwt`, `missingac`, `passwordreset`, `sqlinjection` |
| **java:S2077**       | 10    | Dynamic SQL query (SQL injection)  | Yes -- lesson content for `sqlinjection/*`, `challenges`, `jwt/claimmisuse`                                                                      |
| **java:S2245**       | 5     | Insecure PRNG (`java.util.Random`) | Yes -- lesson content for `cryptography`, `challenges`, `jwt`, `hijacksession`                                                                   |
| **java:S4507**       | 4     | Debug feature left active          | Yes -- lesson content for `sqlinjection`, `ssrf`                                                                                                 |
| **Web:S5725**        | 3     | Missing SRI integrity attribute    | Mixed -- lesson HTML files (`hijacksession`, `spoofcookie`, `vulnerablecomponents`)                                                              |
| **jssecurity:S5696** | 2     | Stored XSS via innerHTML           | Yes -- lesson JS for `csrf`, `challenges`                                                                                                        |
| **java:S4790**       | 1     | Weak hash (MD5)                    | Yes -- `cryptography` lesson                                                                                                                     |
| **java:S5443**       | 1     | Publicly writable directory        | Yes -- `pathtraversal` lesson (ProfileZipSlip)                                                                                                   |
| **javascript:S2068** | 1     | Hard-coded password in JS          | Yes -- `jwt` lesson                                                                                                                              |

**One exception:** `java:S2077` at `LessonConnectionInvocationHandler.java:31`
is in the **container framework**, not lesson code. See
[Section 4](#4-genuine--accidental-issues).

### 3b. SonarQube Security Hotspots (13)

| Probability |     Category      | Count |                                   Locations                                   |
|-------------|-------------------|-------|-------------------------------------------------------------------------------|
| MEDIUM      | Weak cryptography | 2     | `lessons/chromedevtools`, `lessons/httpbasics` (JS `Math.random`)             |
| LOW         | Encrypt data      | 2     | `static/plugins/bootstrap-wysihtml5` (HTTP URLs in bundled lib)               |
| LOW         | ReDoS             | 8     | `static/js/goatApp`, `static/js/libs`, `static/plugins` (regex in bundled JS) |
| LOW         | Other             | 1     | `static/js/libs/text.js` (regex)                                              |

All hotspots are in lesson HTML or bundled third-party JS assets. None are in
application framework code.

### 3c. Semgrep Findings (53)

|                Rule                 |  Sev.   | Count | Intentional? |                                            Files                                             |
|-------------------------------------|---------|-------|--------------|----------------------------------------------------------------------------------------------|
| `formatted-sql-string`              | ERROR   | 8     | Yes          | `lessons/sqlinjection/*`, `lessons/challenges/*`                                             |
| `jdbc-sqli`                         | WARNING | 7     | Yes          | `lessons/sqlinjection/*`                                                                     |
| `unrestricted-request-mapping`      | WARNING | 10    | Mixed        | `container/service/*` (3), `lessons/*` (5), `webwolf/*` (2)                                  |
| `weak-random`                       | WARNING | 6     | Yes          | `lessons/cryptography/*`, `lessons/hijacksession/*`, `lessons/jwt/*`, `lessons/challenges/*` |
| `cookie-missing-httponly`           | WARNING | 5     | Yes          | `lessons/hijacksession/*`, `lessons/jwt/*`, `lessons/spoofcookie/*`                          |
| `cookie-missing-secure-flag`        | WARNING | 3     | Yes          | `lessons/jwt/*`, `lessons/spoofcookie/*`                                                     |
| `cookie-issecure-false`             | WARNING | 3     | Yes          | `lessons/jwt/*`, `lessons/spoofcookie/*`                                                     |
| `tainted-sql-string`                | ERROR   | 3     | Yes          | `lessons/challenges/*`, `lessons/sqlinjection/*`                                             |
| `object-deserialization`            | WARNING | 2     | Yes          | `lessons/deserialization/*`                                                                  |
| `tainted-url-host`                  | ERROR   | 1     | Yes          | `lessons/jwt/claimmisuse/JWTHeaderJKUEndpoint`                                               |
| `use-of-md5`                        | WARNING | 1     | Yes          | `lessons/cryptography/HashingAssignment`                                                     |
| `spring-unvalidated-redirect`       | WARNING | 1     | Yes          | `lessons/openredirect/OpenRedirectRealRedirect`                                              |
| `httpservlet-path-traversal`        | ERROR   | 1     | Mixed        | `lessons/pathtraversal/ProfileUploadRetrieval`                                               |
| `tainted-session-from-http-request` | WARNING | 1     | Yes          | `lessons/cryptography/EncodingAssignment`                                                    |
| `tainted-file-path`                 | ERROR   | 1     | **Genuine**  | `webwolf/FileServer.java:79`                                                                 |

---

## 4. Genuine / Accidental Issues

The following findings appear to be **unintentional** issues in the application
framework or support code (not part of any lesson's deliberately vulnerable
logic):

### 4.1 SQL Injection in Container Framework

- **File:** `src/main/java/org/owasp/webgoat/container/lessons/LessonConnectionInvocationHandler.java:31`
- **Finding:** `statement.execute("SET SCHEMA \"" + user.getUsername() + "\"")`
- **Tool:** SonarQube `java:S2077`, Semgrep (not flagged because it's not a
  direct HTTP-to-SQL flow)
- **Risk:** If a user registers with a username containing SQL metacharacters
  (e.g. `"; DROP TABLE ...--`), the `SET SCHEMA` statement could be exploited.
  The username comes from the authenticated `WebGoatUser` principal.
- **Classification:** **Likely genuine.** This is container infrastructure code,
  not a lesson. A parameterised statement or input validation on the username
  would eliminate the risk.
- **Severity:** MEDIUM (requires authenticated user with crafted username)

### 4.2 Path Traversal in WebWolf FileServer

- **File:** `src/main/java/org/owasp/webgoat/webwolf/FileServer.java:75`
- **Finding:** `destinationDir.toPath().resolve(multipartFile.getOriginalFilename())`
  uses the original filename from the upload without sanitisation. A crafted
  filename like `../../etc/passwd` could write outside the intended directory.
- **Tool:** Semgrep `tainted-file-path` (ERROR)
- **Classification:** **Likely genuine.** WebWolf is the attacker-utility
  companion app, not a lesson endpoint. While WebWolf is only meant for local
  use, the lack of filename sanitisation is an accidental vulnerability.
- **Severity:** MEDIUM (requires authentication; WebWolf only binds to
  localhost by default)

### 4.3 Unrestricted `@RequestMapping` in Container Services

- **Files:**
  - `container/service/LabelDebugService.java:35, :48`
  - `container/service/LessonMenuService.java:45`
  - `container/service/SessionService.java:22`
- **Finding:** `@RequestMapping` without explicit HTTP method means all methods
  (GET, POST, PUT, DELETE, etc.) are accepted, bypassing Spring Security's
  default CSRF protection for GET/HEAD/TRACE/OPTIONS.
- **Tool:** Semgrep `unrestricted-request-mapping` (WARNING)
- **Classification:** **Likely genuine.** These are framework service endpoints,
  not lessons. Using `@GetMapping` where appropriate would tighten security.
- **Severity:** LOW (CSRF risk on read-only endpoints is limited)

### 4.4 Unrestricted `@RequestMapping` in WebWolf FileServer

- **File:** `webwolf/FileServer.java:56`
- **Finding:** Same `@RequestMapping` without HTTP method issue.
- **Tool:** Semgrep `unrestricted-request-mapping` (WARNING)
- **Classification:** **Likely genuine** (same reasoning as 4.3).
- **Severity:** LOW

### 4.5 Missing SRI Integrity Attributes in Lesson HTML

- **Files:**
  - `lessons/hijacksession/html/HijackSession.html:5`
  - `lessons/spoofcookie/html/SpoofCookie.html:5`
  - `lessons/vulnerablecomponents/html/VulnerableComponents.html:5`
- **Finding:** External script/stylesheet tags without `integrity` and
  `crossorigin` attributes.
- **Tool:** SonarQube `Web:S5725` (MINOR)
- **Classification:** **Low-priority genuine.** These load local WebJar assets
  (not CDN), so the practical risk is minimal, but adding SRI is best practice.
- **Severity:** INFO

### 4.6 Legacy `javax.xml.bind:jaxb-api` Dependency

- **Classification:** **Low-priority genuine.** The project already has the
  Jakarta replacement; the legacy `javax` artifact can likely be removed unless
  lesson code directly imports `javax.xml.bind` types.
- **Severity:** INFO

---

## 5. Recommendations

### For Genuine Issues

1. **LessonConnectionInvocationHandler** -- Sanitise or validate usernames
   before embedding in SQL. Prefer a parameterised approach or at minimum
   reject usernames containing `"` or `;`.
2. **WebWolf FileServer** -- Sanitise `getOriginalFilename()` by stripping
   path separators and `..` sequences (e.g.
   `Paths.get(name).getFileName().toString()`).
3. **Unrestricted `@RequestMapping`** -- Replace with `@GetMapping` on
   read-only container endpoints.
4. **Remove `javax.xml.bind:jaxb-api`** if no lesson code requires the
   `javax.*` namespace (the `jakarta.xml.bind-api` is already present).

### For Future Scans

1. **Provide an NVD API key** to the OWASP Dependency-Check profile. Without
   one, the NVD database download (361,577+ records) cannot complete in
   reasonable time. Request a free key at https://nvd.nist.gov/developers/request-an-api-key
   and pass it via `-DnvdApiKey=<key>` or the `NVD_API_KEY` environment
   variable.
2. **Semgrep Pro** would add ~1,860 additional rules (including taint tracking
   and supply-chain analysis). Consider `semgrep login` for the free tier.
3. **SonarQube** already has comprehensive coverage. The current quality gate
   passes on new code; the overall E security rating is expected for a
   deliberately insecure application.

---

*Generated by automated security tooling. Review before acting on any finding.*
