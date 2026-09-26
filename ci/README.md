# Client and independent verifier CI

`.github/workflows/checks.yml` is the active workflow; `ci/github-actions.yml`
is its identical reviewable copy. On pushes and PRs it checks all Node tests,
Python verifier/vendor tests, pinned OPAQUE bytes and reproducibility of
`release-manifest.json` from `web/` plus the local header policy.
The workflow uses pinned actions and read-only repository permissions.
A passing job confirms those checks, not the live site's delivery; run the
independent verifier separately against https://cloud.nimbus.by:9443/vault/.
