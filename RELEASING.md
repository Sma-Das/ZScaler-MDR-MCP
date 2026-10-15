# Release checklist

1. Review changes, run `make ci`, and merge them into `main`.
2. Set repository variable `DOCKERHUB_USERNAME=smadas` and repository secret `DOCKERHUB_TOKEN` with a token authorized to push `zscaler-mdr-mcp`.
3. Push a stable semantic version tag such as `v0.1.0` from the reviewed main commit.
4. Check both container and native-binary release jobs. A GitHub release alone does not prove the Docker Hub publication succeeded.
5. Verify the image is publicly pullable on both Linux architectures and record the immutable digest.
6. Verify native archive checksums and stdio initialization before pinning consumers.

The workflow requires tag ancestry in `origin/main`, reruns checks, publishes `linux/amd64` and `linux/arm64` container images with SBOM/provenance, and creates Linux/macOS/Windows archives for amd64 and arm64. Stable releases get version and `latest` image tags. No prerelease publication is implemented.

Provider API keys never belong in release jobs or public repository secrets. Live investigation validation uses local runtime secrets and prints only projected results.
