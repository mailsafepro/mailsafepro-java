# 🚨 Security Cleanup - All Repositories

**Date:** January 3, 2026  
**Severity:** HIGH  
**Affected Repositories:** 3

---

## 📊 Summary of Issues

### Repository: mailsafepro-java
- **6 incidents** detected by GitGuardian
- **Types:** Generic High Entropy Secrets (5) + Stripe Webhook Secret (1)
- **Commits:** 14f2ec8, c6bf4ec, 9d6b0fb

### Repository: mailsafepro-python  
- **2 incidents** detected by GitGuardian
- **Types:** Generic High Entropy Secrets (2)
- **Commits:** 9f410ea

### Repository: mailsafepro (main)
- **Multiple JWT tokens** in test files
- **Files affected:** test_emails.sh, test_emails2.sh, test_smtp.sh, test_lab_emails.sh, resultados_test.txt

---

## 🔍 Root Causes

1. **JWT Tokens in Test Scripts** - Real authentication tokens committed to repository
2. **Test Results Files** - Output files with sensitive data committed
3. **Stripe Placeholders** - While mostly safe, could be improved
4. **High Entropy Secrets** - Likely test data but flagged by security scanners

---

## ✅ Immediate Actions Required

### 1. Revoke All Exposed JWT Tokens

The JWT tokens in the test files are **REAL** and contain:
- User IDs
- Email addresses  
- Expiration times
- Scopes and permissions

**Action:** These tokens are likely expired, but verify in your database and revoke if still active.

### 2. Clean Up Test Files

Remove sensitive data from test files and use environment variables instead.

---

## 🛠️ Fixes to Apply

### Fix 1: Update .gitignore

Add these patterns to prevent future incidents:

```gitignore
# Test results and logs
resultados_test*.txt
test_results*.txt
*.log
logs/

# Environment and secrets
.env
.env.*
!.env.example
*.key
*.pem
*.p12
*.pfx

# JWT tokens and auth
*token*.txt
*jwt*.txt
*auth*.txt
```

### Fix 2: Clean Test Scripts

Replace hardcoded tokens with environment variables:

**Before:**
```bash
export ACCESS_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...."
```

**After:**
```bash
# Load from .env or prompt user
if [ -z "$ACCESS_TOKEN" ]; then
  echo "❌ ACCESS_TOKEN not set"
  echo "Please run: export ACCESS_TOKEN='your-token'"
  exit 1
fi
```

### Fix 3: Remove Test Result Files

These files should NEVER be committed:
- `resultados_test.txt`
- `resultados_test2.txt`
- Any files with API responses

---

## 📝 Step-by-Step Cleanup

### For mailsafepro (main repository)

```bash
cd /path/to/mailsafepro

# 1. Remove sensitive files
git rm --cached resultados_test.txt resultados_test2.txt
git rm --cached logs/api.log

# 2. Update .gitignore
cat >> .gitignore << 'EOF'

# Test results - NEVER COMMIT
resultados_test*.txt
test_results*.txt

# JWT tokens and auth files
*token*.txt
*jwt*.txt
EOF

# 3. Clean test scripts (manual - see below)

# 4. Commit changes
git add .gitignore
git commit -m "🔒 Security: Remove sensitive test files and update .gitignore"
git push origin main
```

### For mailsafepro-java

```bash
cd /path/to/mailsafepro-java

# Check what secrets were detected
git show 14f2ec8
git show c6bf4ec  
git show 9d6b0fb

# If they're test data/placeholders, document them
# If they're real secrets, follow the cleanup process
```

### For mailsafepro-python

```bash
cd /path/to/mailsafepro-python

# Check what secrets were detected
git show 9f410ea

# Clean up as needed
```

---

## 🔧 Updated Test Scripts

### test_emails.sh (Secure Version)

```bash
#!/bin/bash

# MailSafePro Email Validation Tests
# Requires: ACCESS_TOKEN environment variable

set -e

# Check for required token
if [ -z "$ACCESS_TOKEN" ]; then
  echo "❌ Error: ACCESS_TOKEN not set"
  echo ""
  echo "To get a token:"
  echo "  1. Login to your account"
  echo "  2. Get JWT token from response"
  echo "  3. Export: export ACCESS_TOKEN='your-jwt-token'"
  echo ""
  exit 1
fi

# API Configuration
API_URL="${API_URL:-http://localhost:8000}"

echo "🧪 Running email validation tests..."
echo "API: $API_URL"
echo ""

# Test 1: Single email validation
echo "Test 1: Single email validation"
curl -X POST "$API_URL/validate/email" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'

echo ""
echo "✅ Tests complete"
```

### test_emails2.sh (Secure Version)

```bash
#!/bin/bash

# Load from .env if exists
if [ -f ".env.test" ]; then
  source .env.test
fi

# Validate required variables
if [ -z "$PREMIUM_TOKEN" ]; then
  echo "❌ PREMIUM_TOKEN not set"
  echo "Create .env.test with: PREMIUM_TOKEN=your-token"
  exit 1
fi

# Rest of your tests...
```

### .env.test.example (New File)

```bash
# Test Environment Configuration
# Copy this to .env.test and fill in your values
# NEVER commit .env.test!

# JWT Tokens (get from login endpoint)
ACCESS_TOKEN=your-jwt-token-here
PREMIUM_TOKEN=your-premium-token-here
FREE_TOKEN=your-free-token-here

# API Configuration
API_URL=http://localhost:8000
BATCH_URL=http://localhost:8000/validate/batch
```

---

## 🧹 Git History Cleanup

### Option 1: BFG Repo-Cleaner (Recommended)

```bash
# Install BFG
brew install bfg

# Clone fresh mirror
git clone --mirror https://github.com/mailsafepro/mailsafepro.git
cd mailsafepro.git

# Remove JWT tokens from history
bfg --replace-text <(cat << 'EOF'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI==>***JWT_REMOVED***
EOF
)

# Clean up
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Force push
git push --force
```

### Option 2: git filter-repo

```bash
# Install
pip install git-filter-repo

# Create patterns file
cat > /tmp/secrets.txt << 'EOF'
regex:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+===>***JWT_REMOVED***
EOF

# Filter repository
git filter-repo --replace-text /tmp/secrets.txt

# Force push
git push --force --all
```

---

## 📋 Verification Checklist

### mailsafepro (main)
- [ ] Remove resultados_test*.txt files
- [ ] Update .gitignore
- [ ] Clean test scripts to use env vars
- [ ] Create .env.test.example
- [ ] Add .env.test to .gitignore
- [ ] Commit and push changes
- [ ] Clean git history (optional)

### mailsafepro-java
- [ ] Identify what secrets were detected
- [ ] Remove or document them
- [ ] Update .gitignore if needed
- [ ] Clean git history

### mailsafepro-python
- [ ] Identify what secrets were detected
- [ ] Remove or document them
- [ ] Update .gitignore if needed
- [ ] Clean git history

---

## 🔐 Prevention Measures

### 1. Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
  
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: check-added-large-files
      - id: detect-private-key
      - id: check-json
      - id: check-yaml
EOF

# Initialize
pre-commit install
pre-commit run --all-files
```

### 2. GitHub Secret Scanning

Enable in repository settings:
- Settings → Code security and analysis
- Enable "Secret scanning"
- Enable "Push protection"

### 3. Environment Variable Management

```bash
# Use direnv for automatic env loading
brew install direnv

# Add to ~/.zshrc or ~/.bashrc
eval "$(direnv hook zsh)"

# Create .envrc in project
echo 'dotenv .env.test' > .envrc
direnv allow
```

---

## 📚 Resources

- [GitHub: Removing Sensitive Data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
- [GitGuardian](https://www.gitguardian.com/)
- [Pre-commit Hooks](https://pre-commit.com/)

---

## ⚠️ Important Notes

1. **JWT Tokens:** The exposed tokens are likely expired, but verify in your database
2. **Test Data:** Some "secrets" might be test data - review each one
3. **History Cleanup:** Optional but recommended for public repositories
4. **Team Notification:** If others have cloned the repo, they need to re-clone after history cleanup

---

**Next Steps:** Start with the main repository cleanup, then move to Java and Python repos.
