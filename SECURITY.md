# Security policy

## Supported versions

Open Trestle is experimental. No release is currently supported for production use.

## Reporting a vulnerability

Do not report vulnerabilities in a public issue. Use private vulnerability reporting instead. Open the [Security tab](https://github.com/georgejieh/open-trestle/security) of the repository and choose **Report a vulnerability**, or go directly to the [new advisory form](https://github.com/georgejieh/open-trestle/security/advisories/new).

A report should include the affected revision, the impact, the steps to reproduce it, and any supporting material. Do not include credentials, customer source, tokens, or exploit payloads that would create unnecessary risk.

## Response goals

Maintainers aim to acknowledge a valid report within three business days. They then assess its severity and scope, coordinate a plan to fix it, and publish an advisory when a fix is available. These are response goals, not a warranty or a service-level agreement.

## Security design commitments

The project intends to enforce least privilege, tenant and repository scope, provider-route policy, default-deny networking for execution, and explicit authorization for dynamic validation. These controls, including the network-free check sandbox and the consent that repository tests need, are in the source tree. No signed release includes them yet.
