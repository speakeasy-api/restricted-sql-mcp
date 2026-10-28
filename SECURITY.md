# Security

Report vulnerabilities privately to **security@speakeasy.com**, following
[Speakeasy's vulnerability disclosure policy](https://www.speakeasy.com/legal/security-policy).
Do not disclose exploitable SQL guard bypasses, credentials, or database contents
in public issues or pull requests.

Include the server version or commit, database dialect/version, relevant flags
with secrets removed, expected and actual behavior, and a minimal reproduction
against a synthetic database.

SQL validation and connection-level database privileges are independent defenses.
A bypass of either is security-relevant. Review the README's security model and
[annotation access documentation](docs/column-access.md) before changing them.
