# Contributing to kms-issuer

We're glad you want to make a contribution!

Fork this repository and send in a pull request when you're finished with your changes. Link any relevant issues in too.

Take note of the build status of your pull request, only builds that pass will be accepted. Please also keep to our conventions and style so we can keep this repository as clean as possible.

## License

By contributing your code, you agree to license your contribution under the terms of the APLv2: [Licence](https://github.com/drzzlio/kms-issuer/blob/main/LICENCE)

All files are released with the Apache 2.0 license.

## Dependencies

- [`pre-commit`](https://pre-commit.com/) - required for automated local checks and linting
- [`make`](https://www.gnu.org/software/make/)
- [`kubebuilder`](https://github.com/kubernetes-sigs/kubebuilder) - Kms-Issuer was built using the [Kubebuilder](https://book.kubebuilder.io/) framework, see the [official documentation](https://book.kubebuilder.io/quick-start.html) to get started
- [`Docker`](https://www.docker.com/)
- [`go`](https://golang.org/)
- [`kustomize`](https://kustomize.io/)
- [`kind`](https://kind.sigs.k8s.io/) - for testing
- [`golangci-lint`](https://golangci-lint.run/)
- [`travis CLI`](https://github.com/travis-ci/travis.rb#readme) - for validating changes to `.travis.yml` config file
- [`kubectl`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

## Testing

Run tests:

```console
make test
```
