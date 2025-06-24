# How to Clear Git Commit History

> **Warning:** This is a destructive, irreversible operation. It permanently rewrites repository history. All collaborators must re-clone the repository afterwards. Proceed only if you fully understand the implications.

---

## Why You May Want to Do This

- The commit history contains sensitive data (API keys, passwords) that need to be fully erased.
- The development history contains internal planning notes that should not be public.
- You want a clean, professional history for the public release.

---

## Option 1 — Orphan Branch (Recommended)

This creates a single clean "Initial commit" that contains the current working tree, with no prior history.

```bash
# 1. Create a new orphan branch (no parent commits)
git checkout --orphan clean-main

# 2. Stage all current files
git add -A

# 3. Create the initial commit
git commit -m "Initial release — UniVex v1.0.0"

# 4. Delete the old main branch
git branch -D main

# 5. Rename the orphan branch to main
git branch -m main

# 6. Force-push to GitHub
#    WARNING: this overwrites all history on the remote
git push --force origin main
```

After this, all collaborators must re-clone:

```bash
git clone https://github.com/BitR1ft/UniVex.git
```

---

## Option 2 — git filter-repo (Remove Specific Sensitive Files)

Use this if you only need to remove specific files or strings from history while keeping the rest.

```bash
# Install git-filter-repo
pip install git-filter-repo

# Remove a specific file from all history
git filter-repo --path secrets.txt --invert-paths

# Remove all occurrences of a string (e.g. an API key) from history
git filter-repo --replace-text <(echo 'sk-real-api-key==>REDACTED')

# Force-push after rewriting
git push --force --all origin
git push --force --tags origin
```

> ⚠️ `git filter-repo` must be run on a fresh clone with no other remotes configured.

---

## Option 3 — BFG Repo Cleaner (Remove Secrets)

BFG is faster than `git filter-branch` for large repositories.

```bash
# Download BFG
curl -LO https://repo1.maven.org/maven2/com/madgag/bfg/1.14.0/bfg-1.14.0.jar

# Remove a file from all history
java -jar bfg-1.14.0.jar --delete-files secrets.txt your-repo.git

# Remove passwords/secrets
java -jar bfg-1.14.0.jar --replace-text passwords.txt your-repo.git

# Clean up and push
cd your-repo.git
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push --force --all
```

---

## After Rewriting History

1. **Invalidate all open pull requests** — they will reference commits that no longer exist. Close and re-open them against the new history.
2. **Update all forks** — anyone who forked the repository will have an incompatible history. Notify them to re-fork.
3. **Re-clone locally** — all contributors must delete their local clone and re-clone:
   ```bash
   rm -rf UniVex/
   git clone https://github.com/BitR1ft/UniVex.git
   ```
4. **Rotate any secrets** that were in the history — even after rewriting, anyone who cloned before the rewrite may still have the old history locally.
5. **Check GitHub's cached views** — GitHub caches some commit data. After a force-push, submit a [GitHub support request](https://support.github.com/request) to clear cached views of removed content if the data was sensitive.

---

## Protecting Against Future Secrets in History

Use pre-commit hooks to prevent secrets from being committed:

```bash
# Install pre-commit
pip install pre-commit

# Add .pre-commit-config.yaml to the repository root
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
EOF

pre-commit install
```

Or use GitHub's built-in secret scanning (already enabled for public repositories).

---

*UniVex v1.0.0 | BitR1FT*
