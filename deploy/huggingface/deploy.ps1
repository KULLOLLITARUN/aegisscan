<#
.SYNOPSIS
  Publish the current commit of this repository to a Hugging Face Space (Docker).

.DESCRIPTION
  Hugging Face Spaces are their own git repositories. This script clones your Space into a
  temporary folder, replaces its contents with the files of this repository's current commit
  (leaving out the tests, example vulnerable code and plans, which the server does not need),
  adds the Space description file, commits and pushes.

  Create the Space first (SDK: Docker, hardware: CPU basic) and add the secret
  AEGISSCAN_ACCESS_TOKEN in the Space settings BEFORE the first push, because hosted mode refuses
  to start without it. When git asks for a password, use a Hugging Face access token with write
  access (huggingface.co/settings/tokens), not your account password.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File deploy\huggingface\deploy.ps1 -SpaceUrl https://huggingface.co/spaces/YOUR_NAME/aegisscan
#>
param(
  [Parameter(Mandatory = $true)][string]$SpaceUrl
)

$ErrorActionPreference = 'Stop'

if ($SpaceUrl -notmatch '^https://huggingface\.co/spaces/[^/\s]+/[^/\s]+/?$') {
  throw "SpaceUrl must look like https://huggingface.co/spaces/YOUR_NAME/SPACE_NAME"
}

$repo = (git rev-parse --show-toplevel).Trim()
if (git -C $repo status --porcelain) {
  throw "This repository has uncommitted changes. Commit them first: only committed files are deployed."
}
$commit = (git -C $repo rev-parse --short HEAD).Trim()

$work = Join-Path $env:TEMP ("aegis-space-" + [guid]::NewGuid().ToString('N'))
$tar = Join-Path $env:TEMP ("aegis-export-" + [guid]::NewGuid().ToString('N') + '.tar')
try {
  git clone $SpaceUrl $work
  if ($LASTEXITCODE -ne 0) { throw "Could not clone the Space. Check the URL and your access token." }

  # Start from an empty working tree (keep .git so history is preserved), then add this commit's files.
  Get-ChildItem -Path $work -Force | Where-Object { $_.Name -ne '.git' } | Remove-Item -Recurse -Force

  git -C $repo archive --format=tar HEAD -o $tar
  tar -xf $tar -C $work
  foreach ($skip in 'tests', 'examples', 'Plans', 'deploy') {
    $p = Join-Path $work $skip
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }
  }
  Copy-Item -LiteralPath (Join-Path $repo 'deploy\huggingface\README.md') -Destination (Join-Path $work 'README.md') -Force

  git -C $work add -A
  if (-not (git -C $work status --porcelain)) {
    Write-Host "The Space already has this version. Nothing to push."
    return
  }
  git -C $work commit -q -m "Deploy AegisScan $commit"
  git -C $work push
  if ($LASTEXITCODE -ne 0) { throw "Push failed. If it asked for a password, use a Hugging Face write token." }
  Write-Host ""
  Write-Host "Pushed $commit. Watch the build on the Space page (Logs, then Build)."
}
finally {
  if (Test-Path -LiteralPath $tar) { Remove-Item -LiteralPath $tar -Force }
  if ($work.StartsWith($env:TEMP, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $work)) {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
}
