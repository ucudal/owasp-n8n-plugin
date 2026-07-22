# n8n-crs-lab

WAF (OWASP ModSecurity CRS) delante de n8n, con los logs en OpenSearch para
verlos desde dashboards.

## Requisitos

- Docker y Docker Compose
- En Linux nativo: `vm.max_map_count >= 262144` (el `setup.sh` lo chequea)

## Instalación

```bash
chmod +x setup.sh
./setup.sh
docker-compose up -d
```

Esperar a que finalice el proceso de docker y entrar a las siguientes herramientas:

- n8n (a través del WAF): 


- OpenSearch Dashboards: http://localhost:5601

## Uso básico

Usar n8n normal en http://localhost:8080. 
Todo el trafico pasa por el WAF.

Para ver los logs del WAF, entrá a Dashboards (http://localhost:5601). 
Ya viene con 6 dashboards predefinidos con vistas generales que eliminan todo el "ruido".

- **WAF - Resumen General**
- **WAF - Severidad**
- **WAF - Categorías de Ataque**
- **WAF - Rule ID Ranking**
- **WAF - Impacto en N8N**
- **WAF - Workflows Bloqueados**

## Deteccion vs. bloqueo

Por defecto el WAF solo registra, no bloquea. Para que bloquee, en `.env`:

```
MODSEC_RULE_ENGINE=On
```

y volver a correr `docker-compose up -d`.


## Apagar

```bash
docker-compose down
```
