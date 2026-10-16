# Changesets

Every PR that changes the server adds a changeset: `npx changeset`, pick
patch, minor or major, and describe the change for the CHANGELOG. On main the
Release workflow keeps a "chore: version packages" PR open; merging it tags
`vX.Y.Z`, creates the GitHub release and publishes
`ghcr.io/speakeasy-api/restricted-sql-mcp:X.Y.Z`.
