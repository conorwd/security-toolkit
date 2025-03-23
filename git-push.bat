@echo off
echo ===================================
echo GitHub Quick Commit and Push Tool
echo ===================================

:: Stage all changes
git add .
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to stage changes
    goto end
)
echo Changes staged successfully

:: Get commit message
set /p COMMIT_MSG=Enter commit message: 

:: Commit with the provided message
git commit -m "%COMMIT_MSG%"
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to commit changes
    goto end
)
echo Changes committed successfully

:: Push to GitHub
echo Pushing to GitHub...
git push
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to push to GitHub
    goto end
)
echo Changes pushed to GitHub successfully

:end
echo ===================================
pause 