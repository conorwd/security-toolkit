#!/bin/bash

echo "==================================="
echo "GitHub Quick Commit and Push Tool"
echo "==================================="

# Stage all changes
git add .
if [ $? -ne 0 ]; then
    echo "Error: Failed to stage changes"
    exit 1
fi
echo "Changes staged successfully"

# Get commit message
echo -n "Enter commit message: "
read COMMIT_MSG

# Commit with the provided message
git commit -m "$COMMIT_MSG"
if [ $? -ne 0 ]; then
    echo "Error: Failed to commit changes"
    exit 1
fi
echo "Changes committed successfully"

# Push to GitHub
echo "Pushing to GitHub..."
git push
if [ $? -ne 0 ]; then
    echo "Error: Failed to push to GitHub"
    exit 1
fi
echo "Changes pushed to GitHub successfully"

echo "===================================" 