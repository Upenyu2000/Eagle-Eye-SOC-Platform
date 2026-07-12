$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$RepositoryUrl = "https://github.com/Upenyu2000/Eagle-Eye-SOC-Platform.git"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git is not installed. Install Git for Windows first."
}

if (-not (Test-Path .git)) {
    git init -b main
}

git config user.name "Upenyu Hlangabeza"
if (-not (git config user.email)) {
    git config user.email "upshlangabeza@gmail.com"
}

git add .
$changes = git status --porcelain
if ($changes) {
    git commit -m "Build Eagle Eye unified SOC Windows platform"
}

$remote = git remote get-url origin 2>$null
if ($LASTEXITCODE -eq 0) {
    git remote set-url origin $RepositoryUrl
} else {
    git remote add origin $RepositoryUrl
}

git branch -M main
git push -u origin main

Write-Host "Published to $RepositoryUrl"
