#!/usr/bin/env bash
set -euo pipefail

echo "== Preparando n8n-crs-lab =="

if [ ! -f .env ]; then
  cp .env.example .env
  KEY=$(openssl rand -hex 32)
  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/^N8N_ENCRYPTION_KEY=$/N8N_ENCRYPTION_KEY=${KEY}/" .env
  else
    sed -i "s/^N8N_ENCRYPTION_KEY=$/N8N_ENCRYPTION_KEY=${KEY}/" .env
  fi
  echo "-> .env creado con una N8N_ENCRYPTION_KEY nueva."
else
  echo "-> .env ya existe, no se toca."
fi


mkdir -p rules
for f in \
  "rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf" \
  "rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"
do
  if [ ! -f "$f" ]; then
    echo "# Sin exclusiones por ahora" > "$f"
    echo "-> Creado $f"
  fi
done

if [ ! -f fluent-bit.conf ]; then
  cat > fluent-bit.conf << 'EOF'
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
EOF
  echo "-> Creado fluent-bit.conf"
fi

if [ ! -f parsers.conf ]; then
  cat > parsers.conf << 'EOF'
[PARSER]
    Name        modsec_json
    Format      json
    Time_Key    transaction.time_stamp
    Time_Format %a %b %d %H:%M:%S %Y
    Time_Keep   On
EOF
  echo "-> Creado parsers.conf"
fi

# vm.max_map_count: requerido por OpenSearch en Linux nativo
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  CURRENT=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
  if [ "$CURRENT" -lt 262144 ]; then
    echo "-> vm.max_map_count es $CURRENT, OpenSearch necesita al menos 262144."
    echo "   Corré: sudo sysctl -w vm.max_map_count=262144"
    echo "   Y para que persista al reiniciar, agregá esa línea a /etc/sysctl.conf"
  fi
fi

echo "== Listo. Ahora podés correr: docker-compose up -d =="
