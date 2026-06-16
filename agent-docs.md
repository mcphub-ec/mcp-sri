# Agent-First Documentation: SRI MCP Server

## 1. Contexto General
Servidor MCP para facturación electrónica directa al SRI (Ecuador). Implementa:
- Generación XML según esquema SRI v2.1.0.
- Firma digital XAdES-BES con certificados `.p12` (delegada al microservicio Java en `signing-service/`).
- Comunicación SOAP con RecepcionComprobantesOffline y AutorizacionComprobantesOffline.
- Generación de RIDE (PDF) y estructura ATS.

## 2. Tecnologías Principales
- **FastMCP 3.3.1**: Framework MCP.
- **httpx**: Cliente HTTP asíncrono (firmas REST hacia `signing-service`).
- **zeep**: Cliente SOAP para SRI.
- **lxml**: Parsing y generación XML.
- **cryptography**: Validación de certificados `.p12`.
- **Java/Spring Boot**: Microservicio de firma en `signing-service/`.

## 3. Variables de Entorno Importantes
- `MCP_HOST`, `MCP_PORT` (default 8002), `MCP_TRANSPORT_MODE` (sse|streamable_http).
- `SRI_ENVIRONMENT`: `TEST` (certificados de pruebas) | `PRODUCTION` (certificados reales).
- `CERTIFICATE_PATH`, `CERTIFICATE_PASSWORD`: Ruta al `.p12` y su contraseña.
- `EMITTER_RUC`, `EMITTER_RAZON_SOCIAL`, etc.: Datos del emisor.
- `SIGNING_SERVICE_URL`: URL del microservicio Java (default `http://localhost:18081`).
- `SIGNING_API_KEY`: **Requerido**. Debe coincidir con la config del signing-service Java.

## 4. Reglas de Negocio Estrictas (Ecuador)
- **IVA por defecto 15%** a menos que el item sea explícitamente "Tarifa 0%".
- **Identificaciones**: CEDULA (10 dígitos, código SRI 05), RUC (13 dígitos, código 04),
  PASAPORTE (alfanumérico, código 06), CONSUMIDOR_FINAL (`9999999999999`, código 07).
- **Tipos de comprobante**: 01=Factura, 03=Liquidación, 04=Nota de Crédito, 05=Nota de Débito,
  06=Guía de Remisión, 07=Comprobante de Retención.
- **Ambientes**: `1`=Pruebas, `2`=Producción. Controlado por `SRI_ENVIRONMENT`.

## 5. Consideraciones Técnicas
- La clave de acceso SRI (49 dígitos) se deriva del RUC + fecha + tipo + secuencial y se loguea
  enmascarada; un filtro de logging dedicado redaces RUCs, tokens y passwords en logs.
- El servidor Python NO firma XML directamente: delega al microservicio Java para usar
  Apache Santuario + BouncyCastle, que son las librerías de referencia para XAdES-BES.
- **CORS del signing-service está restringido** a orígenes específicos vía
  `SIGNING_ALLOWED_ORIGINS` (default vacío = ninguna petición cross-origin aceptada).
- **Auth del signing-service**: requiere header `X-Signing-Key` con valor `SIGNING_API_KEY`.
  Si la variable no está configurada o vale `changeme`, TODAS las peticiones son rechazadas.

## 6. Herramientas Principales (16 totales)
- `consultar_informacion_ruc`: Consulta pública del SRI.
- `generar_xml_v232`: Construye XML según esquema v2.1.0.
- `firmar_xades_bes`: Delega firma al microservicio Java.
- `comunicar_sri_recepcion`: Envía a RecepcionComprobantesOffline.
- `comunicar_sri_autorizacion`: Consulta autorizacion en SRI.
- `generar_ride_pdf`: Genera PDF del comprobante.
- `generar_estructura_ats`: XML para el Anexo Transaccional Simplificado.
- Y 9 más para retenciones, guías de remisión, etc.

## 7. Instrucciones para Edición de Código
- El cálculo del IVA está implementado en `services/taxes.py` (funciones puras, fácil de testear).
- El cliente SOAP está en `services/core.py` (zeep).
- El parsing XML robusto está en `services/xml_parser.py` con lxml.
- Al añadir una nueva tool, sigue el patrón: `@mcp.tool()` + type hints completos + docstring
  con secciones (Descripción, Parámetros, Retorno, Ejemplo).
- **NUNCA** loguear la clave de acceso SRI completa, el password del `.p12`, ni el RUC del cliente.

## 8. Seguridad
- `signing-service/` está expuesto SOLO en la red Docker interna (puerto 18081), nunca al host.
- Las peticiones MCP↔signing usan header `X-Signing-Key` para autenticación mutua.
- En producción, despliega con `docker-compose up -d` y configura `SIGNING_API_KEY` en un
  secret manager (NO en `.env` trackeado).
- `certs/` y `*.p12` están en `.gitignore`. El archivo `firma.p12` debe tener permisos 600.

## 9. Tests
- `tests/test_sri.py`: 1 test de `generate_access_key` y `validate_access_key`.
- Pendiente: añadir tests para `services/taxes.py` y `services/xml_parser.py` (parsing XAdES).
