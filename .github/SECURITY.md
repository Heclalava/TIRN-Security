# Security Policy

## Supported Versions

TIRN Security is currently an alpha-stage project.

Security reports are currently accepted for:

| Version     | Supported |
| ----------- | --------- |
| 1.0.1-alpha | Yes       |

Because TIRN Security is an alpha release, security-related behavior may change between releases.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub Issues.**

If you believe you have found a security vulnerability in TIRN Security, use GitHub's **Private Vulnerability Reporting** feature on this repository.

Private vulnerability reporting allows the details of a potential vulnerability to be shared with the maintainers without publicly disclosing the issue.

When reporting a vulnerability, please provide as much of the following information as possible:

* TIRN Security version
* Android version
* device and relevant environment details
* a clear description of the vulnerability
* steps required to reproduce it
* expected and observed behavior
* security impact
* proof of concept, if available
* relevant logs or other supporting information

Please avoid including personal information, credentials, authentication tokens, or other unrelated sensitive data.

## What Should Be Reported Privately

Examples include:

* firewall bypasses;
* unintended network access;
* failures of fail-closed behavior;
* privilege or permission issues;
* vulnerabilities in the web UI or CGI interfaces;
* unsafe handling of application identity, UID, or policy data;
* vulnerabilities that could allow one application or user context to affect another;
* unintended exposure of sensitive information;
* vulnerabilities in packaged runtime components.

Normal bugs, crashes, feature requests, usability problems, and non-security-related issues should continue to be reported through **GitHub Issues**.

## Disclosure

Security reports will be evaluated and, where appropriate, addressed before public disclosure.

If a vulnerability results in a security advisory, the repository's GitHub Security Advisory mechanism may be used to coordinate the fix and subsequent disclosure.

Because TIRN Security is currently an alpha project, security reports may result in changes to implementation, configuration, or supported behavior before a stable release.
