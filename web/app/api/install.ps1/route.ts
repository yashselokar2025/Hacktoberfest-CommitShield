import { NextResponse } from "next/server";

const SCRIPT = `# SecureVibeCoded installer — Windows PowerShell
# Usage: iwr https://hacktoberfest-commit-shield-git-main-yash-selokars-projects.vercel.app/api/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  SecureVibeCoded Installer" -ForegroundColor Cyan -NoNewline
Write-Host " - Evidence-based Git security gate"
Write-Host ""

# Check Python
$py = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python (\\d+)\\.(\\d+)") {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -ge 3 -and $minor -ge 9) {
                $py = $cmd
                Write-Host "  Python $($Matches[1]).$($Matches[2]) found" -ForegroundColor Green
                break
            }
        }
    } catch {}
}

if (-not $py) {
    Write-Host "  Python 3.9+ required but not found." -ForegroundColor Red
    Write-Host "  Download from https://python.org"
    exit 1
}

# Check gitleaks
if (-not (Get-Command gitleaks -ErrorAction SilentlyContinue)) {
    Write-Host ""
    Write-Host "  Gitleaks not found — required for scanning." -ForegroundColor Yellow
    Write-Host "  Download from: https://github.com/gitleaks/gitleaks/releases"
    Write-Host ""
}

# Install
Write-Host "  Installing securevibecoded..." -NoNewline
& $py -m pip install --quiet "git+https://github.com/yashselokar2025/Hacktoberfest-CommitShield.git"
Write-Host " done" -ForegroundColor Green

Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  cd your-git-repo"
Write-Host "  svc install      # Add pre-commit hook"
Write-Host "  svc scan         # Manual scan"
Write-Host ""
Write-Host "Done! Happy coding. " -ForegroundColor Green
`;

export async function GET() {
  return new NextResponse(SCRIPT, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": 'attachment; filename="install.ps1"',
      "Cache-Control": "public, max-age=3600",
    },
  });
}
