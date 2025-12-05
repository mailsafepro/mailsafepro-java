# Contributing to MailSafePro

Thank you for your interest in contributing to MailSafePro Email Validation API! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Assume good intentions

## Getting Started

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git
- Redis (via Docker)

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/mailsafepro-api.git
   cd mailsafepro-api
   ```

2. **Create Virtual Environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

5. **Start Services**
   ```bash
   docker compose up -d
   ```

6. **Run Tests**
   ```bash
   pytest tests/ -v
   ```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test improvements
- `chore/` - Maintenance tasks

### 2. Make Changes

- Write clear, concise code
- Follow Python PEP 8 style guide (enforced by black/flake8)
- Add type hints to all functions
- Write comprehensive docstrings
- Update tests for your changes

### 3. Run Quality Checks

```bash
# Format code
black app/ tests/

# Sort imports
isort app/ tests/

# Lint
flake8 app/ tests/

# Security scan
bandit -r app/ -ll

# Type check
mypy app/

# Run tests
pytest tests/ --cov=app --cov-report=html
```

### 4. Commit Changes

We use [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git add .
git commit -m "feat: add email typo suggestion feature"
# or
git commit -m "fix: resolve SMTP timeout in Docker"
# or
git commit -m "docs: update API authentication guide"
```

Commit types:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Test changes
- `chore:` - Maintenance tasks
- `perf:` - Performance improvements
- `ci:` - CI/CD changes

### 5. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:
- Clear title describing the change
- Description of what changed and why
- Reference to any related issues
- Screenshots/videos for UI changes
- Test results

## Code Style Guidelines

### Python

- **Line length**: 120 characters max
- **Formatting**: Use `black` (enforced by pre-commit)
- **Import sorting**: Use `isort` with black profile
- **Type hints**: Required for all public functions
- **Docstrings**: Google style, required for public APIs

Example:
```python
from typing import Optional

async def validate_email(
    email: str,
    check_smtp: bool = False,
    timeout: float = 5.0
) -> dict:
    """Validates an email address with optional SMTP check.
    
    Args:
        email: Email address to validate
        check_smtp: Whether to perform SMTP verification
        timeout: Maximum time for validation in seconds
        
    Returns:
        Dictionary containing validation results with keys:
        - valid: bool
        - risk_score: int
        - details: dict
        
    Raises:
        ValidationError: If email format is invalid
        TimeoutError: If validation exceeds timeout
    """
    # Implementation
    pass
```

### Testing

- Write tests for all new features
- Maintain >85% code coverage
- Use pytest fixtures for setup
- Mock external services
- Test edge cases and error conditions

Example:
```python
import pytest
from app.validation import validate_email

@pytest.mark.asyncio
async def test_validate_email_success():
    """Test successful email validation."""
    result = await validate_email("test@example.com")
    assert result["valid"] is True
    assert result["risk_score"] < 50

@pytest.mark.asyncio
async def test_validate_email_invalid_format():
    """Test validation with invalid email format."""
    with pytest.raises(ValidationError):
        await validate_email("invalid-email")
```

## Pull Request Guidelines

### Before Submitting

- [ ] All tests pass locally
- [ ] Code is formatted with black
- [ ] No linting errors from flake8
- [ ] No security issues from bandit
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated (for significant changes)
- [ ] Commit messages follow Conventional Commits

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests pass locally
```

## Reporting Bugs

### Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.
Email: security@mailsafepro.com

### Bug Reports

Open an issue with:
- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, etc.)
- Logs/screenshots if applicable

## Feature Requests

Open an issue with:
- Clear, descriptive title
- Problem you're trying to solve
- Proposed solution
- Alternatives considered
- Additional context

## Questions?

- Check existing issues and documentation
- Ask in GitHub Discussions
- Email: support@mailsafepro.com

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to MailSafePro! 🚀
