# GitHub Workflows Documentation

This directory contains GitHub Actions workflows for CI/CD automation.

## Workflows

### 🔄 `ci-cd.yml` - Main CI/CD Pipeline

Comprehensive pipeline that runs on every push and PR.

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Version tags (`v*`)

**Jobs:**

1. **Lint** - Code quality checks
   - Black (formatting)
   - isort (import sorting)
   - Flake8 (linting)
   - mypy (type checking)
   - Bandit (security)

2. **Security** - Vulnerability scanning
   - Safety check (dependencies)
   - Trivy (filesystem scan)
   - Results uploaded to GitHub Security

3. **Test** - Automated testing
   - Unit tests with pytest
   - Integration tests with Redis
   - Coverage reporting to Codecov

4. **Build** - Docker image creation
   - Multi-platform build (amd64, arm64)
   - Push to GitHub Container Registry
   - Trivy scan of Docker image

5. **Deploy Staging** - Auto-deploy to staging
   - Triggered on `develop` branch
   - Updates Kubernetes deployment
   - Runs smoke tests

6. **Deploy Production** - Release deployment
   - Triggered on version tags
   - Updates production Kubernetes
   - Creates GitHub release
   - Runs smoke tests

7. **Performance** - Load testing
   - k6 performance tests
   - Runs on staging environment

**Secrets Required:**
- `KUBE_CONFIG_STAGING` - Base64 encoded kubeconfig for staging
- `KUBE_CONFIG_PRODUCTION` - Base64 encoded kubeconfig for production
- `GITHUB_TOKEN` - Auto-provided by GitHub

---

### 🎉 `release.yml` - Auto Release

Automated release creation on version tags.

**Triggers:**
- Version tags matching `v*.*.*`

**Actions:**
- Generates changelog from commits
- Creates GitHub release with notes
- Includes Docker pull commands
- Notifies Slack (if configured)

**Secrets Required:**
- `SLACK_WEBHOOK_URL` (optional) - For Slack notifications

---

### 🤖 `dependabot.yml` - Dependency Updates

Automated dependency update PRs.

**Updates:**
- Python dependencies (weekly, Mondays)
- GitHub Actions (weekly)
- Docker base images (weekly)

**Features:**
- Groups minor/patch updates
- Security updates always separate
- Auto-labels PRs
- Conventional commit messages

---

## Setup Instructions

### 1. Configure Secrets

Add these secrets in GitHub Settings → Secrets and variables → Actions:

```bash
# Kubernetes configs (base64 encoded)
KUBE_CONFIG_STAGING
KUBE_CONFIG_PRODUCTION

# Optional: Slack notifications
SLACK_WEBHOOK_URL
```

### 2. Enable GitHub Container Registry

Repository Settings → Actions → General → Workflow permissions:
- Enable "Read and write permissions"

### 3. Enable Dependabot

Repository Settings → Security → Dependabot:
- Enable Dependabot alerts
- Enable Dependabot security updates

### 4. Configure Branch Protection

Settings → Branches → Add rule for `main`:
- Require status checks before merging
  - `lint`
  - `security`
  - `test`
  - `build`
- Require branches to be up to date
- Require pull request reviews

---

## Usage

### Creating a Release

```bash
# Update version in pyproject.toml
# Update CHANGELOG.md

# Commit changes
git add .
git commit -m "chore: bump version to 2.2.0"
git push

# Create and push tag
make tag VERSION=v2.2.0
# or manually:
git tag -a v2.2.0 -m "Release v2.2.0"
git push origin v2.2.0
```

This will automatically:
1. Run full CI pipeline
2. Build and push Docker image
3. Deploy to production
4. Create GitHub release
5. Notify Slack

### Testing Workflows Locally

Use [act](https://github.com/nektos/act) to test workflows locally:

```bash
# Install act
brew install act

# Test lint job
act -j lint

# Test entire workflow
act push
```

### Monitoring Workflows

- View runs: Actions tab in GitHub
- Check logs: Click on any workflow run
- Download artifacts: Available in workflow run page

---

## Workflow Status Badges

Add to README.md:

```markdown
[![CI/CD](https://github.com/YOUR_ORG/mailsafepro/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/YOUR_ORG/mailsafepro/actions/workflows/ci-cd.yml)
[![codecov](https://codecov.io/gh/YOUR_ORG/mailsafepro/branch/main/graph/badge.svg)](https://codecov.io/gh/YOUR_ORG/mailsafepro)
```

---

## Troubleshooting

### Workflow fails on build

- Check Docker build logs
- Verify all files are included (check .dockerignore)
- Test locally: `make docker-build`

### Tests fail in CI but pass locally

- Check environment variables
- Verify Redis is running in CI (service container)
- Check Python version matches

### Deployment fails

- Verify Kubernetes secrets are correct
- Check cluster connectivity
- Review deployment logs: `make k8s-logs`

### Dependabot PRs failing

- May be breaking changes in dependencies
- Review PR, test locally before merging
- Can configure ignored dependencies in dependabot.yml

---

## Best Practices

1. **Always test locally first**
   ```bash
   make ci-local
   ```

2. **Keep workflows DRY**
   - Use composite actions for repeated steps
   - Share configs via artifacts

3. **Secure secrets**
   - Never commit secrets to repo
   - Use environment-specific secrets
   - Rotate secrets regularly

4. **Monitor costs**
   - GitHub Actions free tier: 2,000 minutes/month
   - Optimize caching to reduce build times
   - Use self-hosted runners for heavy workloads

5. **Document changes**
   - Update CHANGELOG.md
   - Use conventional commits
   - Tag releases semantically (semver)

---

## Additional Resources

- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Kubernetes Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [Conventional Commits](https://www.conventionalcommits.org/)
