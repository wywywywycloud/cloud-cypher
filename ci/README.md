# GitHub Actions configuration

`github-actions.yml` is ready to copy to `.github/workflows/checks.yml`.
The publishing OAuth credential did not have GitHub's `workflow` scope, so no active workflow is installed by this release. This is a permission limit on CI setup, not a test result. Local reproducible checks and their reports are in `reports/README.md`.

Copying the file requires repository access that allows workflow changes. The workflow uses pinned official actions and only `contents: read`.
