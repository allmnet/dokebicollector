$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$Builds = @(
    @{
        Name = 'Windows x64'
        Target = $null
        Command = { Invoke-CheckedNative { cargo build --release } 'cargo build --release' }
        Output = 'target/release/dokebicollector.exe'
        Required = $true
    },
    @{
        Name = 'Linux x64 MUSL'
        Target = 'x86_64-unknown-linux-musl'
        Command = {
            Invoke-CheckedNative { rustup target add x86_64-unknown-linux-musl } 'rustup target add x86_64-unknown-linux-musl'
            $previousLinker = $env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER
            $env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = 'rust-lld'
            try {
                Invoke-CheckedNative { cargo build --release --target x86_64-unknown-linux-musl } 'cargo build --release --target x86_64-unknown-linux-musl'
            } finally {
                if ($null -eq $previousLinker) {
                    Remove-Item Env:\CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER -ErrorAction SilentlyContinue
                } else {
                    $env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = $previousLinker
                }
            }
        }
        Output = 'target/x86_64-unknown-linux-musl/release/dokebicollector'
        Required = $true
    },
    @{
        Name = 'macOS Intel'
        Target = 'x86_64-apple-darwin'
        Command = {
            Invoke-CheckedNative { rustup target add x86_64-apple-darwin } 'rustup target add x86_64-apple-darwin'
            Invoke-CheckedNative { cargo build --release --target x86_64-apple-darwin } 'cargo build --release --target x86_64-apple-darwin'
        }
        Output = 'target/x86_64-apple-darwin/release/dokebicollector'
        Required = $false
    },
    @{
        Name = 'macOS Apple Silicon'
        Target = 'aarch64-apple-darwin'
        Command = {
            Invoke-CheckedNative { rustup target add aarch64-apple-darwin } 'rustup target add aarch64-apple-darwin'
            Invoke-CheckedNative { cargo build --release --target aarch64-apple-darwin } 'cargo build --release --target aarch64-apple-darwin'
        }
        Output = 'target/aarch64-apple-darwin/release/dokebicollector'
        Required = $false
    }
)

$Results = New-Object System.Collections.Generic.List[object]

foreach ($Build in $Builds) {
    Write-Host "==> Building $($Build.Name)" -ForegroundColor Cyan
    try {
        & $Build.Command
        $outputPath = Join-Path $ProjectRoot $Build.Output
        if (-not (Test-Path $outputPath)) {
            throw "Build finished but output was not found: $($Build.Output)"
        }
        $Results.Add([pscustomobject]@{
            Name = $Build.Name
            Status = 'ok'
            Output = $Build.Output
            Error = $null
        })
    } catch {
        $Results.Add([pscustomobject]@{
            Name = $Build.Name
            Status = 'failed'
            Output = $Build.Output
            Error = $_.Exception.Message
        })
        if ($Build.Required) {
            break
        }
    }
}

Write-Host ""
Write-Host "Build summary" -ForegroundColor Cyan
$Results | Format-Table Name, Status, Output, Error -AutoSize

$RequiredFailure = $Results | Where-Object { $_.Status -ne 'ok' -and ($Builds | Where-Object Name -eq $_.Name).Required }
if ($RequiredFailure) {
    exit 1
}

$MacFailure = $Results | Where-Object { $_.Name -like 'macOS*' -and $_.Status -ne 'ok' }
if ($MacFailure) {
    Write-Host ""
    Write-Host "macOS builds need Apple SDK/Xcode linker tooling. On Windows they may fail at the link step even after Rust targets are installed." -ForegroundColor Yellow
}
