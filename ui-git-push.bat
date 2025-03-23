@echo off
echo ===================================
echo UI Repository - GitHub Push Tool
echo ===================================

:: Navigate to the UI directory
cd ui

echo Current directory: UI repository at %CD%

:: Stage all changes
git add .
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to stage changes
    goto end
)
echo Changes staged successfully

:: Get commit message
set /p COMMIT_MSG=Enter commit message for UI repository: 

:: Commit with the provided message
git commit -m "%COMMIT_MSG%"
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to commit changes
    goto end
)
echo Changes committed successfully

:: Push to GitHub
echo Pushing UI changes to GitHub...
git push
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to push to GitHub
    goto end
)
echo UI repository changes pushed to GitHub successfully

:: Return to parent directory
cd ..

:end
echo ===================================
pause 