#!/usr/bin/env bash
# Usage: ./push_to_github.sh <your-github-username> [repo-name]
# 1) Create an EMPTY repo named logsentinel at https://github.com/new (no README/license)
# 2) Run this script. Your link will be https://github.com/<username>/<repo-name>
set -e
USER_NAME="${1:?GitHub username required}"; REPO="${2:-logsentinel}"
git init -b main
git add .
git commit -m "LogSentinel: log analyzer and attack correlator (capstone)"
git remote add origin "https://github.com/$USER_NAME/$REPO.git"
git push -u origin main
echo "Done -> https://github.com/$USER_NAME/$REPO"
