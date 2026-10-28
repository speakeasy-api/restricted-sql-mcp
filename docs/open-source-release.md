# Open-source release preparation

This repository is licensed under GNU Affero General Public License version 3
(`AGPL-3.0-only`). The repository is still private; changing its visibility is a
separate publication step.

## Tunnel dependency and distributions

`internal/tunnel/tunnel.go` imports `github.com/speakeasy-api/gram/tunnel/agent`
from Gram commit `1f98a3b3f439` (`go.mod` pins the full pseudo-version). That
package imports `tunnel/wire` and inherits the module's root
[AGPL version 3 license](https://github.com/speakeasy-api/gram/blob/1f98a3b3f439/LICENSE).
This repository uses the same license version, without a special exception or
changes to the upstream dependency. LICENSE contains the same unmodified license
text as that pinned Gram revision. Other dependencies keep their own licenses.

Both Dockerfiles include LICENSE, NOTICE and THIRD_PARTY_NOTICES. Release images carry the SPDX
license identifier, source repository and exact source revision as OCI labels.
When publishing a binary or container, make its corresponding source and build
instructions available for that exact revision under the terms of LICENSE.
GitHub release source archives, go.mod/go.sum and the Dockerfiles identify the
version and build inputs; verify that recipients can actually access them.
THIRD_PARTY_NOTICES is generated from licenses and notices in linked Go package
and module directories. It includes `pg_query_go`'s PostgreSQL license and parser
copyright, and the MIT No Attribution license for `segmentio/asm` (which the
license classifier does not identify). Regenerate it after dependency changes
with `python3 scripts/update-third-party-notices.py`; review additional notices
when introducing C, assembly or other embedded code.

## Publication handoff

- Review all reachable Git history before switching visibility. `docs/superpowers`
  was removed from current tracking and ignored at the owner's request; older
  commits and tags still contain it. No history rewrite has been performed.
- Enable GitHub private vulnerability reporting if desired; SECURITY.md already
  provides Speakeasy's published private reporting address.
- Check GHCR package visibility independently of repository visibility and verify
  anonymous pulls of the release intended for public use.
- The root `package.json` stays `private: true`: it is Changesets tooling, not an
  npm distribution. Source licensing and GitHub visibility are independent.
- Public pull requests run unit/race tests and vet on GitHub-hosted runners
  without repository secrets. Image publication remains restricted to main and
  the existing maintainer-controlled release workflows.
