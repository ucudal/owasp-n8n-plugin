#Requires -Version 5.1
$ErrorActionPreference = "Stop"

Write-Host "== Preparando n8n-crs-lab =="

# 1. .env con una N8N_ENCRYPTION_KEY nueva
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"

    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $key = -join ($bytes | ForEach-Object { $_.ToString("x2") })

    (Get-Content ".env") -replace '^N8N_ENCRYPTION_KEY=$', "N8N_ENCRYPTION_KEY=$key" |
        Set-Content ".env"

    Write-Host "-> .env creado con una N8N_ENCRYPTION_KEY nueva."
} else {
    Write-Host "-> .env ya existe, no se toca."
}

# 2. Archivos de exclusion de reglas (vacios si no existen)
New-Item -ItemType Directory -Path "rules" -Force | Out-Null

$exclusionFiles = @(
    "rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf",
    "rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"
)
foreach ($f in $exclusionFiles) {
    if (-not (Test-Path $f)) {
        "# Sin exclusiones por ahora" | Set-Content $f
        Write-Host "-> Creado $f"
    }
}

# 3. fluent-bit.conf
if (-not (Test-Path "fluent-bit.conf")) {
    @"
[SERVICE]
    Flush         5
    Daemon        Off
    Log_Level     info
    Parsers_File  parsers.conf

[INPUT]
    Name              forward
    Listen            0.0.0.0
    Port              24224

[FILTER]
    Name              parser
    Match             waf.*
    Key_Name          log
    Parser            modsec_json
    Reserve_Data      On

[OUTPUT]
    Name                es
    Match               waf.*
    Host                opensearch
    Port                9200
    Index               modsec-logs
    Suppress_Type_Name  On
    Retry_Limit         5
"@ | Set-Content "fluent-bit.conf"
    Write-Host "-> Creado fluent-bit.conf"
}

# 4. parsers.conf
if (-not (Test-Path "parsers.conf")) {
    @"
[PARSER]
    Name        modsec_json
    Format      json
    Time_Key    transaction.time_stamp
    Time_Format %a %b %d %H:%M:%S %Y
    Time_Keep   On
"@ | Set-Content "parsers.conf"
    Write-Host "-> Creado parsers.conf"
}

# 5. vm.max_map_count no aplica en Windows (Docker Desktop lo maneja en su VM interna)

Write-Host "== Listo. Ahora podes correr: docker-compose up -d =="