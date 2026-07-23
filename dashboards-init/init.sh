#!/bin/sh
# Crea el index pattern y los dashboards de OpenSearch Dashboards vía Saved Objects API.

set -e

OSD="http://opensearch-dashboards:5601"

echo "Instalando curl y jq..."
apk add --no-cache curl jq >/dev/null 2>&1

echo "Esperando a OpenSearch Dashboards..."
until curl -s -o /dev/null "$OSD/api/status"; do
  echo "  ...todavia no responde, reintentando"
  sleep 3
done
echo "Dashboards arriba."

put_object() {
  code=$(curl -s -o /tmp/resp.json -w "%{http_code}" -X POST \
    "$OSD/api/saved_objects/$1/$2?overwrite=true" \
    -H "osd-xsrf: true" -H "Content-Type: application/json" \
    -d "$3")
  echo "  [$code] $1/$2"
  if [ "$code" -ge 400 ]; then
    cat /tmp/resp.json
    echo ""
  fi
}

# ---------------------------------------------------------------------------
# 1. Index pattern
# ---------------------------------------------------------------------------
echo "Creando index pattern modsec-logs*..."
put_object index-pattern modsec-logs \
  "$(jq -n '{attributes:{title:"modsec-logs*",timeFieldName:"@timestamp"}}')"

put_object config 2.15.0 \
  "$(jq -n '{attributes:{defaultIndex:"modsec-logs"}}')"

IDX_REF='{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"modsec-logs"}'

search_source() {
  jq -nr --arg q "$1" --argjson ref "$IDX_REF" \
    '{query:{query:$q,language:"kuery"},filter:[],indexRefName:"kibanaSavedObjectMeta.searchSourceJSON.index"} | tostring'
}

# ---------------------------------------------------------------------------
# 2. Visualizaciones
# ---------------------------------------------------------------------------

echo "Creando visualizaciones..."

# --- Metric: total de eventos de seguridad -------------------------------
VS=$(jq -nr '{
  title:"WAF - Total eventos de seguridad", type:"metric",
  params:{addTooltip:true,addLegend:false,type:"metric",
    metric:{percentageMode:false,useRanges:false,colorSchema:"Green to Red",
      metricColorMode:"None",colorsRange:[{from:0,to:10000}],
      labels:{show:true},invertColors:false,
      style:{bgFill:"#000",bgColor:false,labelColor:false,subText:"",fontSize:60}}},
  aggs:[{id:"1",enabled:true,type:"count",schema:"metric",params:{}}]
} | tostring')
SS=$(jq -nr --arg q 'transaction.messages: { message: * }' \
  '{query:{query:$q,language:"kuery"},filter:[],indexRefName:"kibanaSavedObjectMeta.searchSourceJSON.index"} | tostring')
BODY=$(jq -n --arg vs "$VS" --arg ss "$SS" --argjson ref "$IDX_REF" \
  '{attributes:{title:"WAF - Total eventos de seguridad",visState:$vs,uiStateJSON:"{}",description:"",
    kibanaSavedObjectMeta:{searchSourceJSON:$ss}},references:[$ref]}')
put_object visualization viz-metric-total "$BODY"

# --- Metric: eventos críticos (severidad 0/1/2) ---------------------------
VS=$(jq -nr '{
  title:"WAF - Eventos críticos", type:"metric",
  params:{addTooltip:true,addLegend:false,type:"metric",
    metric:{percentageMode:false,useRanges:false,colorSchema:"Red",
      metricColorMode:"Labels",colorsRange:[{from:0,to:10000}],
      labels:{show:true},invertColors:false,
      style:{bgFill:"#000",bgColor:false,labelColor:true,subText:"",fontSize:60}}},
  aggs:[{id:"1",enabled:true,type:"count",schema:"metric",params:{}}]
} | tostring')
SS=$(jq -nr --arg q 'transaction.messages: { details.severity: "0" } or transaction.messages: { details.severity: "1" } or transaction.messages: { details.severity: "2" }' \
  '{query:{query:$q,language:"kuery"},filter:[],indexRefName:"kibanaSavedObjectMeta.searchSourceJSON.index"} | tostring')
BODY=$(jq -n --arg vs "$VS" --arg ss "$SS" --argjson ref "$IDX_REF" \
  '{attributes:{title:"WAF - Eventos críticos",visState:$vs,uiStateJSON:"{}",description:"",
    kibanaSavedObjectMeta:{searchSourceJSON:$ss}},references:[$ref]}')
put_object visualization viz-metric-critical "$BODY"

# --- Histograma: eventos en el tiempo -------------------------------------
VS=$(jq -nr '{
  title:"WAF - Eventos en el tiempo", type:"histogram",
  params:{type:"histogram",grid:{categoryLines:false},
    categoryAxes:[{id:"CategoryAxis-1",type:"category",position:"bottom",show:true,style:{},scale:{type:"linear"},labels:{show:true,filter:true,truncate:100},title:{}}],
    valueAxes:[{id:"ValueAxis-1",name:"LeftAxis-1",type:"value",position:"left",show:true,style:{},scale:{type:"linear",mode:"normal"},labels:{show:true,rotate:0,filter:false,truncate:100},title:{text:"Cantidad"}}],
    seriesParams:[{show:true,type:"histogram",mode:"stacked",data:{label:"Count",id:"1"},valueAxis:"ValueAxis-1",drawLinesBetweenPoints:true,showCirclesOnLines:true,interpolate:"linear",lineWidth:2}],
    addTooltip:true,addLegend:true,legendPosition:"right",times:[],addTimeMarker:false},
  aggs:[
    {id:"1",enabled:true,type:"count",schema:"metric",params:{}},
    {id:"2",enabled:true,type:"date_histogram",schema:"segment",params:{field:"@timestamp",interval:"auto",min_doc_count:1,extended_bounds:{}}}
  ]
} | tostring')
SS=$(search_source 'transaction.messages: { message: * }')
BODY=$(jq -n --arg vs "$VS" --arg ss "$SS" --argjson ref "$IDX_REF" \
  '{attributes:{title:"WAF - Eventos en el tiempo",visState:$vs,uiStateJSON:"{}",description:"",
    kibanaSavedObjectMeta:{searchSourceJSON:$ss}},references:[$ref]}')
put_object visualization viz-timeline "$BODY"

# --- Pie: distribución por severidad --------------------------------------
VS=$(jq -nr '{
  title:"WAF - Distribución por severidad", type:"pie",
  params:{type:"pie",addTooltip:true,addLegend:true,legendPosition:"right",isDonut:true,
    labels:{show:false,values:true,last_level:true,truncate:100}},
  aggs:[
    {id:"1",enabled:true,type:"count",schema:"metric",params:{}},
    {id:"2",enabled:true,type:"filters",schema:"segment",params:{filters:[
      {input:{query:"transaction.messages: { details.severity: \"0\" }",language:"kuery"},label:"0 - Emergency"},
      {input:{query:"transaction.messages: { details.severity: \"1\" }",language:"kuery"},label:"1 - Alert"},
      {input:{query:"transaction.messages: { details.severity: \"2\" }",language:"kuery"},label:"2 - Critical"},
      {input:{query:"transaction.messages: { details.severity: \"3\" }",language:"kuery"},label:"3 - Error"},
      {input:{query:"transaction.messages: { details.severity: \"4\" }",language:"kuery"},label:"4 - Warning"},
      {input:{query:"transaction.messages: { details.severity: \"5\" }",language:"kuery"},label:"5 - Notice"}
    ]}}
  ]
} | tostring')
SS=$(search_source 'transaction.messages: { message: * }')
BODY=$(jq -n --arg vs "$VS" --arg ss "$SS" --argjson ref "$IDX_REF" \
  '{attributes:{title:"WAF - Distribución por severidad",visState:$vs,uiStateJSON:"{}",description:"",
    kibanaSavedObjectMeta:{searchSourceJSON:$ss}},references:[$ref]}')
put_object visualization viz-pie-severity "$BODY"

# --- Barras: categorías de ataque -----------------------------------------
VS=$(jq -nr '{
  title:"WAF - Categorías de ataque", type:"horizontal_bar",
  params:{type:"histogram",grid:{categoryLines:false},
    categoryAxes:[{id:"CategoryAxis-1",type:"category",position:"left",show:true,style:{},scale:{type:"linear"},labels:{show:true,filter:true,truncate:100},title:{}}],
    valueAxes:[{id:"ValueAxis-1",name:"BottomAxis-1",type:"value",position:"bottom",show:true,style:{},scale:{type:"linear",mode:"normal"},labels:{show:true,rotate:0,filter:false,truncate:100},title:{text:"Cantidad"}}],
    seriesParams:[{show:true,type:"histogram",mode:"stacked",data:{label:"Count",id:"1"},valueAxis:"ValueAxis-1",drawLinesBetweenPoints:true,showCirclesOnLines:true,interpolate:"linear",lineWidth:2}],
    addTooltip:true,addLegend:false,legendPosition:"right",times:[],addTimeMarker:false},
  aggs:[
    {id:"1",enabled:true,type:"count",schema:"metric",params:{}},
    {id:"2",enabled:true,type:"filters",schema:"segment",params:{filters:[
      {input:{query:"transaction.messages: { details.tags: \"attack-lfi\" }",language:"kuery"},label:"LFI"},
      {input:{query:"transaction.messages: { details.tags: \"attack-rfi\" }",language:"kuery"},label:"RFI"},
      {input:{query:"transaction.messages: { details.tags: \"attack-sqli\" }",language:"kuery"},label:"SQLi"},
      {input:{query:"transaction.messages: { details.tags: \"attack-xss\" }",language:"kuery"},label:"XSS"},
      {input:{query:"transaction.messages: { details.tags: \"attack-rce\" }",language:"kuery"},label:"RCE"},
      {input:{query:"transaction.messages: { details.tags: \"attack-disclosure\" }",language:"kuery"},label:"Disclosure"},
      {input:{query:"transaction.messages: { details.tags: \"attack-protocol\" }",language:"kuery"},label:"Protocol"},
      {input:{query:"transaction.messages: { details.tags: \"attack-generic\" }",language:"kuery"},label:"Generic"}
    ]}}
  ]
} | tostring')
SS=$(search_source 'transaction.messages: { message: * }')
BODY=$(jq -n --arg vs "$VS" --arg ss "$SS" --argjson ref "$IDX_REF" \
  '{attributes:{title:"WAF - Categorías de ataque",visState:$vs,uiStateJSON:"{}",description:"",
    kibanaSavedObjectMeta:{searchSourceJSON:$ss}},references:[$ref]}')
put_object visualization viz-bar-categories "$BODY"

# --- Tabla: conteo unico de rule ID ----------------------------------------
VS=$(jq -nr '{
  title:"WAF - Conteo de Rule ID", type:"table",
  params:{perPage:10,showPartialRows:false,showMetricsAtAllLevels:false,showTotal:false,totalFunc:"sum",percentageCol:""},
  aggs:[
    {id:"1",enabled:true,type:"count",schema:"metric",params:{}},
    {id:"2",enabled:true,type:"terms",schema:"bucket",params:{field:"transaction.messages.details.ruleId.keyword",orderBy:"1",order:"desc",size:200,otherBucket:false,otherBucketLabel:"Other",missingBucket:false,missingBucketLabel:"Missing"}}
  ]
} | tostring')
SS=$(search_source '')
BODY=$(jq -n --arg vs "$VS" --arg ss "$SS" --argjson ref "$IDX_REF" \
  '{attributes:{title:"WAF - Conteo de Rule ID",visState:$vs,uiStateJSON:"{}",
    description:"Conteo único de reglas WAF/ModSecurity que se disparan, ordenado de mayor a menor, para identificar cuáles reglas ajustar durante pruebas de ataque.",
    kibanaSavedObjectMeta:{searchSourceJSON:$ss}},references:[$ref]}')
put_object visualization viz-ruleid-count "$BODY"

# ---------------------------------------------------------------------------
# 3. Saved search: detalle de eventos
# ---------------------------------------------------------------------------
echo "Creando saved search de detalle..."
SS=$(search_source 'transaction.messages: { message: * }')
BODY=$(jq -n --arg ss "$SS" --argjson ref "$IDX_REF" \
  '{attributes:{title:"WAF - Detalle de eventos",description:"",
    columns:["@timestamp","transaction.client_ip","transaction.request.method","transaction.request.uri","transaction.messages.details.ruleId","transaction.messages.details.severity","transaction.messages.details.tags"],
    sort:[["@timestamp","desc"]],
    kibanaSavedObjectMeta:{searchSourceJSON:$ss}},references:[$ref]}')
put_object search search-raw-events "$BODY"

# ---------------------------------------------------------------------------
# 4. Dashboards
# ---------------------------------------------------------------------------
echo "Creando dashboards..."

panel() {
  jq -n --arg i "$1" --argjson x "$2" --argjson y "$3" --argjson w "$4" --argjson h "$5" \
    '{version:"2.15.0",gridData:{x:$x,y:$y,w:$w,h:$h,i:$i},panelIndex:$i,embeddableConfig:{},panelRefName:("panel_"+$i)}'
}
panel_ref() {
  jq -n --arg n "panel_$1" --arg t "$2" --arg id "$3" '{name:$n,type:$t,id:$id}'
}

# --- Dashboard general -----------------------------------------------------
PANELS=$(jq -s '.' \
  <(panel 1 0 0 12 8) \
  <(panel 2 12 0 12 8) \
  <(panel 3 24 0 24 8) \
  <(panel 4 0 8 24 16) \
  <(panel 5 24 8 24 16) \
  <(panel 6 0 24 48 20))
REFS=$(jq -s '.' \
  <(panel_ref 1 visualization viz-metric-total) \
  <(panel_ref 2 visualization viz-metric-critical) \
  <(panel_ref 3 visualization viz-timeline) \
  <(panel_ref 4 visualization viz-pie-severity) \
  <(panel_ref 5 visualization viz-bar-categories) \
  <(panel_ref 6 search search-raw-events))
BODY=$(jq -n --argjson panels "$PANELS" --argjson refs "$REFS" '{
  attributes:{
    title:"WAF - Resumen General",
    hits:0,
    description:"Vistazo rápido en vivo: total de eventos, eventos críticos, línea de tiempo, severidad, categorías de ataque y detalle.",
    panelsJSON:($panels|tostring),
    optionsJSON:"{\"useMargins\":true,\"hidePanelTitles\":false}",
    version:1,
    timeRestore:true,
    timeFrom:"now-24h",
    timeTo:"now",
    refreshInterval:{pause:false,value:10000},
    kibanaSavedObjectMeta:{searchSourceJSON:"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}
  },
  references:$refs
}')
put_object dashboard dash-general "$BODY"

# --- Dashboard severidad -----------------------------------------------------
PANELS=$(jq -s '.' \
  <(panel 1 0 0 24 20) \
  <(panel 2 24 0 24 8) \
  <(panel 3 0 20 48 20))
REFS=$(jq -s '.' \
  <(panel_ref 1 visualization viz-pie-severity) \
  <(panel_ref 2 visualization viz-metric-critical) \
  <(panel_ref 3 search search-raw-events))
BODY=$(jq -n --argjson panels "$PANELS" --argjson refs "$REFS" '{
  attributes:{
    title:"WAF - Severidad",
    hits:0,
    description:"Detalle de eventos por severidad.",
    panelsJSON:($panels|tostring),
    optionsJSON:"{\"useMargins\":true,\"hidePanelTitles\":false}",
    version:1,
    timeRestore:true,
    timeFrom:"now-24h",
    timeTo:"now",
    refreshInterval:{pause:false,value:10000},
    kibanaSavedObjectMeta:{searchSourceJSON:"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}
  },
  references:$refs
}')
put_object dashboard dash-severity "$BODY"

# --- Dashboard categorías de ataque ------------------------------------------
PANELS=$(jq -s '.' \
  <(panel 1 0 0 48 20) \
  <(panel 2 0 20 48 20))
REFS=$(jq -s '.' \
  <(panel_ref 1 visualization viz-bar-categories) \
  <(panel_ref 2 search search-raw-events))
BODY=$(jq -n --argjson panels "$PANELS" --argjson refs "$REFS" '{
  attributes:{
    title:"WAF - Categorías de Ataque",
    hits:0,
    description:"Detalle de eventos por categoría de ataque (LFI, SQLi, XSS, etc.).",
    panelsJSON:($panels|tostring),
    optionsJSON:"{\"useMargins\":true,\"hidePanelTitles\":false}",
    version:1,
    timeRestore:true,
    timeFrom:"now-24h",
    timeTo:"now",
    refreshInterval:{pause:false,value:10000},
    kibanaSavedObjectMeta:{searchSourceJSON:"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}
  },
  references:$refs
}')
put_object dashboard dash-categories "$BODY"

# --- Dashboard ranking de rule ID -------------------------------------------
PANELS=$(jq -s '.' \
  <(panel 1 0 0 24 15))
REFS=$(jq -s '.' \
  <(panel_ref 1 visualization viz-ruleid-count))
BODY=$(jq -n --argjson panels "$PANELS" --argjson refs "$REFS" '{
  attributes:{
    title:"WAF - Rule ID Ranking",
    hits:0,
    description:"Dashboard para identificar las reglas WAF/ModSecurity que se disparan con mayor frecuencia al atacar la aplicación, para priorizar su ajuste.",
    panelsJSON:($panels|tostring),
    optionsJSON:"{\"useMargins\":true,\"hidePanelTitles\":false}",
    version:1,
    timeRestore:true,
    timeFrom:"now-7d",
    timeTo:"now",
    refreshInterval:{pause:true,value:0},
    kibanaSavedObjectMeta:{searchSourceJSON:"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}
  },
  references:$refs
}')
put_object dashboard dash-ruleid-ranking "$BODY"

echo "Listo. Dashboards disponibles: WAF - Resumen General, WAF - Severidad, WAF - Categorías de Ataque, WAF - Rule ID Ranking."
