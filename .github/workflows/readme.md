The `test-build` workflow does `make test` then builds and pushes a
multiarch(amd64,arm64) image to `ghcr.io/drzzlio/kms-issuer:sha-abc1234` for
any commit to main.

Commits to main will also trigger `release-drafter` to prepare a draft release.

If `test-build` succeeds then the `e2e` workflow will run to do e2e tests on
the potential release artifact. This relies on workload identity federation to
the [drzzl GCP project](https://github.com/drzzlio/gitops/tree/master/apps/kmsissuer-test) where a test KMS key and service account are made available.

When a release draft is promoted, the `release-build` workflow will attach
release artifacts.
