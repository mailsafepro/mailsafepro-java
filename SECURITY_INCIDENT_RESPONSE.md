# 🚨 Security Incident Response - NuGet API Key Exposure

**Date:** January 3, 2026  
**Severity:** HIGH  
**Status:** IN PROGRESS

---

## 📋 Incident Summary

GitGuardian detected an exposed NuGet API Key in the repository `mailsafepro/mailsafepro-csharp`.

**Exposed Key:** `oy2ouftuh*********************ey*` (partially redacted)

**Files affected:**
- `PUBLISH_CSHARP_MANUAL.md`
- `sdks/csharp/publish-to-nuget.sh`

---

## ✅ Immediate Actions Taken

1. ✅ Removed API key from current files
2. ✅ Replaced with environment variable `$NUGET_API_KEY`
3. ✅ Created `.env.example` with placeholder
4. ✅ Created `SECURITY.md` with best practices
5. ✅ Enhanced publish script with validation
6. ✅ Added `.gitignore` for sensitive files

---

## 🚨 CRITICAL: Actions Required by You

### 1. Revoke the Compromised API Key (URGENT!)

```bash
# Go to NuGet and revoke the key immediately:
open https://www.nuget.org/account/apikeys

# Find and DELETE the key that starts with:
# oy2ouftuh... (see GitGuardian alert for full key)
```

### 2. Create a New API Key

```bash
# After revoking, create a new API key at:
open https://www.nuget.org/account/apikeys

# Recommended settings:
# - Name: "MailSafePro SDK Publishing"
# - Expiration: 365 days
# - Scopes: Push new packages and package versions
# - Glob Pattern: MailSafePro*
```

### 3. Clean Git History

The old API key is still in git history. You need to remove it:

#### Option A: Using BFG Repo-Cleaner (Recommended)

```bash
# Install BFG
brew install bfg  # macOS
# or download from: https://rtyley.github.io/bfg-repo-cleaner/

# Clone a fresh copy
git clone --mirror https://github.com/mailsafepro/mailsafepro-csharp.git

# Remove the API key from history
cd mailsafepro-csharp.git
bfg --replace-text <(echo 'oy2ouftuh***REDACTED***==>***REMOVED***')

# Clean up
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Force push (WARNING: This rewrites history!)
git push --force
```

#### Option B: Using git filter-repo

```bash
# Install git-filter-repo
pip install git-filter-repo

# Clone a fresh copy
git clone https://github.com/mailsafepro/mailsafepro-csharp.git
cd mailsafepro-csharp

# Create a file with the text to replace
echo 'oy2ouftuh***REDACTED***' > /tmp/secret.txt

# Remove from history
git filter-repo --replace-text /tmp/secret.txt

# Force push (WARNING: This rewrites history!)
git push --force --all
```

#### Option C: Contact GitHub Support

If the repository is public and you want GitHub to help:

1. Go to: https://support.github.com/contact
2. Select: "Remove sensitive data"
3. Provide the repository URL and commit hashes

### 4. Notify Team Members

If others have cloned the repository:

```bash
# They need to re-clone after history is cleaned
git clone https://github.com/mailsafepro/mailsafepro-csharp.git
```

---

## 🔒 Prevention Measures Implemented

1. ✅ Environment variable usage enforced
2. ✅ Script validation for API key presence
3. ✅ `.env.example` with placeholders
4. ✅ Enhanced `.gitignore` for secrets
5. ✅ Security documentation created
6. ✅ Pre-commit validation (recommended to add)

---

## 📝 Recommended: Add Pre-commit Hook

Prevent future incidents with a pre-commit hook:

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
        exclude: package.lock.json
EOF

# Initialize
pre-commit install
pre-commit run --all-files
```

---

## 📊 Impact Assessment

**Potential Impact:** HIGH
- The API key could be used to publish malicious packages
- Could overwrite existing packages
- Could delete packages

**Actual Impact:** To be determined
- Check NuGet package history for unauthorized changes
- Review package download logs

---

## 🔍 Verification Steps

After completing the actions above:

1. ✅ Verify old key is revoked
2. ✅ Verify new key works
3. ✅ Verify git history is clean
4. ✅ Verify no unauthorized packages published
5. ✅ Update CI/CD with new key (if applicable)

---

## 📚 Resources

- [NuGet API Keys](https://www.nuget.org/account/apikeys)
- [GitHub: Removing Sensitive Data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
- [GitGuardian](https://www.gitguardian.com/)

---

## ✅ Checklist

- [ ] API key revoked on NuGet
- [ ] New API key created
- [ ] Git history cleaned
- [ ] Team members notified
- [ ] CI/CD updated (if applicable)
- [ ] Pre-commit hooks installed
- [ ] Incident documented
- [ ] Lessons learned documented

---

**Next Review:** After all checklist items are completed
