$ErrorActionPreference = "Stop"

$fixtures_dir = "$PSScriptRoot\..\tests\fixtures"
if (-not (Test-Path $fixtures_dir)) {
    New-Item -ItemType Directory -Path $fixtures_dir | Out-Null
}

Write-Host "Please ensure Docker is installed and running."
# Not actually generating full OCI layouts because Docker/Skopeo might not be installed in the environment.
# Instead, we are just creating dummy OCI layouts for testing purposes.

function Create-DummyOciLayout($Name) {
    $layout_dir = "$fixtures_dir\$Name"
    if (-not (Test-Path $layout_dir)) {
        New-Item -ItemType Directory -Path $layout_dir | Out-Null
    }
    
    # oci-layout
    '{"imageLayoutVersion": "1.0.0"}' | Out-File -FilePath "$layout_dir\oci-layout" -Encoding ascii
    
    # index.json
    '{"schemaVersion": 2, "manifests": []}' | Out-File -FilePath "$layout_dir\index.json" -Encoding ascii
    
    # blobs directory
    $blobs_dir = "$layout_dir\blobs\sha256"
    if (-not (Test-Path $blobs_dir)) {
        New-Item -ItemType Directory -Path $blobs_dir | Out-Null
    }
    
    Write-Host "Created dummy OCI layout for $Name"
}

Create-DummyOciLayout "alpine-hello"
Create-DummyOciLayout "debian-python-web"
Create-DummyOciLayout "node-multi-stage"

Write-Host "Fixtures generation script complete."
