# 🇪🇨 MCP SRI Nativo

Servidor Model Context Protocol (MCP) para la integración con **el Servicio de Rentas Internas (SRI)**.

Parte del ecosistema oficial de [MCP Hub Ecuador](https://github.com/mcphub-ec/hub).

> [!IMPORTANT]
> **🤖 Nota para Agentes IA:** Antes de interactuar con este servidor, por favor revisa el [Agent Cheatsheet](https://github.com/mcphub-ec/hub/blob/main/agent-cheatsheet.md) en nuestro Hub principal para comprender las reglas de negocio, cálculo de IVA (15%) y formatos de identificación de Ecuador.

## 🚀 Características

-   Generación automática de XML nativo según esquema oficial SRI (v2.1.0).
-   Firma digital local XAdES-BES utilizando tu propio certificado `.p12`.
-   Transmisión y autorización automática vía SOAP.
-   **Arquitectura Enterprise:** Imágenes Docker ultra-ligeras con _Healthchecks_ nativos, logs estructurados en JSON y validación continua de seguridad.

## 🛠️ Herramientas Disponibles

-   `flujo_completo_factura`: Ejecuta todo el flujo de facturación electrónica en una sola llamada.
-   `generar_factura_xml`: Genera el XML de la factura y calcula la clave de acceso.
-   `firmar_xml`: Firma el XML generado utilizando el estándar XAdES-BES.
-   `consultar_informacion_ruc`: Obtiene información pública de un contribuyente desde el SRI.

## 📦 Instalación y Configuración

### 1\. Variables de Entorno

Este servidor es completamente _stateless_. Copia el archivo `.env.example` a `.env` y configura tus datos. **Nunca hagas commit de este archivo.**

```env
EMITTER_RUC="0912345678001"
EMITTER_BUSINESS_NAME="Mi Empresa S.A."
EMITTER_ADDRESS="Av. Principal 123"
CERTIFICATE_PATH="/ruta/absoluta/a/tu_firma.p12"
CERTIFICATE_PASSWORD="tu_password_de_firma"
SRI_ENVIRONMENT="TEST"
```

### 2\. Despliegue con Docker (Recomendado)

Para entornos de producción o pruebas limpias, recomendamos usar nuestra imagen oficial alojada en GitHub Container Registry (`ghcr.io`).

**Vía Docker CLI:**

```bash
docker run -d \
  --name mcp-sri \
  --env-file .env \
  ghcr.io/mcphub-ec/mcp-sri:latest
```

**Vía Docker Compose:**

```yaml
services:
  mcp-sri:
    image: ghcr.io/mcphub-ec/mcp-sri:latest
    container_name: mcp-sri
    env_file:
      - .env
    restart: unless-stopped
```

### 3\. Uso con Claude Desktop (Local)

Si deseas conectarlo directamente a tu cliente de Claude para desarrollo local, añade la siguiente configuración a tu archivo `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-sri": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--env-file",
        "/ruta/absoluta/a/tu/.env",
        "ghcr.io/mcphub-ec/mcp-sri:latest"
      ]
    }
  }
}
```

_(Nota: También puedes correrlo directamente con `python -m server` si clonas el repositorio y manejas tu propio entorno virtual)._

## 🔒 Seguridad y Gobernanza

Este proyecto sigue estándares estrictos de seguridad:

-   **Stateless:** No almacena credenciales ni certificados en bases de datos.
-   **Escaneo de Vulnerabilidades:** Cada Pull Request es analizado automáticamente con `bandit` y `detect-secrets`.
-   **Responsible Disclosure:** Si encuentras una vulnerabilidad, por favor no abras un Issue público. Revisa nuestro [SECURITY.md](https://github.com/mcphub-ec/hub/blob/main/SECURITY.md) y contáctanos directamente a `security@mcphub.ec`.

## 🤝 Contribuir

Si deseas proponer mejoras, por favor revisa nuestra [Guía de Contribución](https://github.com/mcphub-ec/hub/blob/main/CONTRIBUTING.md) en el repositorio central. ¡Todos los Pull Requests que pasen los checks de CI/CD son bienvenidos!
