# GitHub Push Guide

This guide will help you push the SecureChat project to GitHub.

## Prerequisites

1. **GitHub Account**: Make sure you have a GitHub account
2. **Git Installed**: Verify with `git --version`
3. **Repository Created**: Create a new repository on GitHub (private or public)

## Step-by-Step Instructions

### 1. Initialize Git Repository
```bash
# Navigate to your project directory
cd /path/to/SecureChat

# Initialize git repository
git init
```

### 2. Add Files to Staging
```bash
# Add all files
git add .

# Or add specific files
# git add README.md
# git add backend/
# git add frontend/
# git add docs/
```

### 3. Commit Changes
```bash
git commit -m "Initial commit: SecureChat - Web-based Secure Messaging App

- Complete implementation with AES-256-GCM encryption
- RSA-OAEP key exchange and RSA-PSS digital signatures
- Interactive Attack Lab demonstrating security defenses
- Real-time WebSocket messaging
- Comprehensive documentation and testing"
```

### 4. Add Remote Repository
```bash
# Replace 'yourusername' and 'repository-name' with your actual GitHub details
git remote add origin https://github.com/yourusername/repository-name.git

# Example:
# git remote add origin https://github.com/alialshahrani/SecureChat.git
```

### 5. Push to GitHub
```bash
# Push to main branch
git branch -M main
git push -u origin main

# If you get authentication errors, you may need to:
# 1. Use HTTPS with personal access token
# 2. Or set up SSH keys
```

### 6. Alternative: Using SSH
```bash
# If you prefer SSH (recommended for security)
git remote add origin git@github.com:yourusername/repository-name.git

# Example:
# git remote add origin git@github.com:alialshahrani/SecureChat.git

# Then push
git push -u origin main
```

## Authentication Methods

### Option 1: HTTPS with Personal Access Token
1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate a new token with `repo` permissions
3. Use the token as your password when prompted

### Option 2: SSH Keys (Recommended)
1. Generate SSH key: `ssh-keygen -t ed25519 -C "your_email@example.com"`
2. Add public key to GitHub: `cat ~/.ssh/id_ed25519.pub`
3. Copy the output and add it to GitHub SSH keys

## Verify Push
```bash
# Check remote repository
git remote -v

# Check status
git status

# View commit history
git log --oneline
```

## Post-Push Actions

### 1. Create GitHub Pages (Optional)
To host documentation:
```bash
# Go to repository settings on GitHub
# Under "Pages", select source: "main" branch, "/ (root)"
# Your docs will be available at: https://yourusername.github.io/repository-name/
```

### 2. Add GitHub Actions (Optional)
Create `.github/workflows/test.yml` for automated testing:
```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.8
    - name: Install dependencies
      run: pip install -r requirements.txt
    - name: Run tests
      run: python test_integration.py
```

### 3. Add Repository Topics
On GitHub, add topics like:
- secure-messaging
- encryption
- cybersecurity
- python
- flask
- aes-gcm
- rsa

### 4. Create Releases
For version management:
1. Go to "Releases" on GitHub
2. Create new release
3. Tag version (e.g., v1.0.0)
4. Add release notes

## Troubleshooting

### Common Issues

**Authentication Failed**:
```bash
# Clear cached credentials
git config --global --unset credential.helper
# Or for macOS
git credential-osxkeychain erase
```

**Large Files**:
```bash
# Check for large files
find . -type f -size +10M

# Remove from history if needed
git filter-branch --tree-filter 'rm -f large-file.zip' HEAD
```

**Line Ending Issues**:
```bash
# Configure line endings
git config core.autocrlf input  # Linux/Mac
git config core.autocrlf true   # Windows
```

## Final Verification

After pushing, verify everything is working:
1. Visit your GitHub repository
2. Check that all files are present
3. Verify README.md renders correctly
4. Test that the project can be cloned by others

## Security Reminders

- ✅ **Never commit sensitive data** (API keys, passwords, private keys)
- ✅ **Use .gitignore** to exclude temporary and sensitive files
- ✅ **Review commit history** before pushing
- ✅ **Use SSH keys** instead of passwords when possible
- ✅ **Enable 2FA** on your GitHub account

---

**🎉 Congratulations! Your SecureChat project is now on GitHub!**

For any issues, refer to:
- [GitHub Documentation](https://docs.github.com/)
- [Git Documentation](https://git-scm.com/doc)