"""
SRI Electronic Billing MCP Server
==================================
MCP server for direct SRI Ecuador electronic billing.

Implemented based on the exact logic of the facturador-sri repository:
- XML: Invoice structure per SRI schema (version 2.1.0)
- Signature: XAdES-BES with RSA-SHA256 (replicating Apache Santuario / Bouncy Castle)
- SOAP: Communication with RecepcionComprobantesOffline and AutorizacionComprobantesOffline

Reference: https://github.com/ma74ni/facturador-sri
"""

import os
import sys
import json
import base64
import hashlib
import random
import time
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Any
from pathlib import Path
from io import BytesIO

# --- Dependencias externas ---
from dotenv import load_dotenv
from lxml import etree
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
from cryptography.hazmat.primitives.hashes import SHA256, SHA1
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate
from cryptography.hazmat.backends import default_backend
from zeep import Client as ZeepClient
from zeep.transports import Transport
from zeep.exceptions import Fault as ZeepFault
import httpx

# --- MCP SDK ---
from mcp.server.fastmcp import FastMCP

# ==============================================================================
# Configuración
# ==============================================================================

# Cargar .env desde la misma carpeta que server.py
_env_path = Path(__file__).parent / ".env"
load_dotenv(_env_path)

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s", "level":"%(levelname)s", "name":"%(name)s", "message":"%(message)s"}',
)
logger = logging.getLogger("sri-mcp")

# Validación inicial (Enterprise Logging)
if not os.getenv("EMITTER_RUC") or not os.getenv("CERTIFICATE_PATH"):
    logger.warning("Faltan variables de entorno clave (EMITTER_RUC o CERTIFICATE_PATH). "
                   "Asegúrate de inyectarlas en tiempo de ejecución en producción.")

# --- Constantes del SRI (extraídas textualmente del repositorio de referencia) ---

SRI_URLS = {
    "TEST": {
        "reception": os.getenv(
            "SRI_RECEPTION_URL_TEST",
            "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl",
        ),
        "authorization": os.getenv(
            "SRI_AUTHORIZATION_URL_TEST",
            "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl",
        ),
    },
    "PRODUCTION": {
        "reception": os.getenv(
            "SRI_RECEPTION_URL_PROD",
            "https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl",
        ),
        "authorization": os.getenv(
            "SRI_AUTHORIZATION_URL_PROD",
            "https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl",
        ),
    },
}

# Namespaces (exactos del Java SignatureService.java)
XADES_NS = "http://uri.etsi.org/01903/v1.3.2#"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

# Mapeo de tipo de identificación (exacto del TypeScript xml-generator.service.ts)
ID_TYPE_MAP = {
    "CEDULA": "05",
    "RUC": "04",
    "PASAPORTE": "06",
    "CONSUMIDOR_FINAL": "07",
    "IDENTIFICACION_EXTERIOR": "08",
}



# --- Lógica central importada de services/core.py ---
from services.core import (
    generate_access_key,
    validate_access_key,
    generate_invoice_xml,
    _load_p12,
    _get_zeep_client,
    send_invoice_to_sri,
    check_authorization_sri,
    _extract_access_key
)

mcp = FastMCP(
    "SRI Electronic Billing",
    host=os.getenv("MCP_HOST", "0.0.0.0"),  # nosec B104 — configurable via MCP_HOST env
    port=int(os.getenv("MCP_PORT", "8002")),
    instructions=(
        "MCP server for direct SRI Ecuador electronic billing. "
        "Implements the full invoice issuance pipeline: XML generation, XAdES-BES digital signing, "
        "SOAP submission to SRI, and authorization polling. "
        "ENV VARS required: EMITTER_RUC, EMITTER_BUSINESS_NAME, EMITTER_ADDRESS, "
        "CERTIFICATE_PATH, CERTIFICATE_PASSWORD, SRI_ENVIRONMENT (TEST|PRODUCTION). "
        "TYPICAL WORKFLOW: "
        "  1. flujo_completo_factura() — use this for end-to-end invoice issuance in ONE call. "
        "  2. Or step-by-step: generar_factura_xml() → firmar_xml() → enviar_al_sri() → consultar_autorizacion(). "
        "DOCUMENT TYPES (codDoc): '01'=Invoice, '04'=Credit note, '05'=Debit note, "
        "  '06'=Waybill, '07'=Retention. "
        "ADDITIONAL TOOLS: "
        "  · consultar_informacion_ruc() — fetches taxpayer info (name, status) from SRI public registry. "
        "ENVIRONMENTS: 'TEST' → celcer.sri.gob.ec | 'PRODUCTION' → cel.sri.gob.ec. "
        "WARNING: PRODUCTION submissions are permanent and legally binding."
    ),
)


@mcp.tool()
def generar_factura_xml(
    secuencial: str,
    tipo_identificacion_comprador: str,
    identificacion_comprador: str,
    razon_social_comprador: str,
    email_comprador: str,
    items: list[dict],
    fecha_emision: str = "",
    forma_pago: str = "01",
    direccion_comprador: str = "",
    telefono_comprador: str = "",
    ruc_emisor: str = "",
    razon_social_emisor: str = "",
    nombre_comercial_emisor: str = "",
    direccion_emisor: str = "",
    codigo_establecimiento: str = "",
    codigo_punto_emision: str = "",
    ambiente: str = "",
    obligado_contabilidad: str = "",
) -> dict:
    """⚠️ MUTATION — Generate invoice XML in SRI v2.1.0 schema format.

    Produces the complete SRI-compliant XML structure, auto-calculates totals
    and 15% VAT, and generates the 49-digit access key. Emitter data is pulled
    from env vars if not explicitly provided.

    REQUIRED PARAMETERS:
      secuencial (str): Invoice sequential number (up to 9 digits). Example: "1"
      tipo_identificacion_comprador (str): Buyer ID type.
                                           Values: "CEDULA" | "RUC" | "PASAPORTE" | "CONSUMIDOR_FINAL"
      identificacion_comprador (str): Buyer ID number. Example: "0912345678"
                                      Use any value for CONSUMIDOR_FINAL (normalized to 9999999999999)
      razon_social_comprador (str): Buyer full name or company name.
                                    Use "CONSUMIDOR FINAL" for final consumer.
      email_comprador (str): Buyer email address.
      items (list[dict]): Invoice line items. Each item requires:
                          {"mainCode": "PROD-001",  # Product code
                           "description": "Laptop",  # Product description
                           "quantity": 2,             # Quantity (number)
                           "unitPrice": 850.50,       # Unit price WITHOUT VAT
                           "discount": 0}             # Monetary discount (default 0)

    OPTIONAL PARAMETERS:
      fecha_emision (str): Issue date in YYYY-MM-DD or DD/MM/YYYY format. Default: today.
      forma_pago (str): SRI payment code. Common: "01"=Cash, "19"=Credit card, "20"=Transfer.
      direccion_comprador (str): Buyer address.
      telefono_comprador (str): Buyer phone number.
      ruc_emisor (str): Issuer RUC. Falls back to EMITTER_RUC env var.
      razon_social_emisor (str): Issuer name. Falls back to EMITTER_BUSINESS_NAME env var.
      nombre_comercial_emisor (str): Trade name. Falls back to EMITTER_TRADE_NAME env var.
      direccion_emisor (str): Issuer address. Falls back to EMITTER_ADDRESS env var.
      codigo_establecimiento (str): Establishment code 3 digits (default "001").
      codigo_punto_emision (str): Emission point code 3 digits (default "001").
      ambiente (str): Valid values: "TEST" | "PRODUCTION". Falls back to SRI_ENVIRONMENT env var.
      obligado_contabilidad (str): "SI" | "NO". Falls back to EMITTER_OBLIGADO_CONTABILIDAD env var.

    RETURNS:
      {"success": True, "xml_content": "<factura...>", "access_key": "49-digit key",
       "formatted_number": "001-001-000000001",
       "totals": {"subtotal", "total_discount", "base_imponible", "iva_15_percent", "total"}}

    EXAMPLE CALL:
      generar_factura_xml(secuencial="1", tipo_identificacion_comprador="CONSUMIDOR_FINAL",
                          identificacion_comprador="9999999999999",
                          razon_social_comprador="CONSUMIDOR FINAL",
                          email_comprador="test@test.com",
                          items=[{"mainCode": "SRV-001", "description": "Service",
                                  "quantity": 1, "unitPrice": 100.0, "discount": 0}])
    """
    try:
        # Cargar defaults desde .env
        ruc_emisor = ruc_emisor or os.getenv("EMITTER_RUC", "")
        razon_social_emisor = razon_social_emisor or os.getenv("EMITTER_BUSINESS_NAME", "")
        nombre_comercial_emisor = nombre_comercial_emisor or os.getenv("EMITTER_TRADE_NAME", razon_social_emisor)
        direccion_emisor = direccion_emisor or os.getenv("EMITTER_ADDRESS", "")
        codigo_establecimiento = codigo_establecimiento or os.getenv("EMITTER_ESTABLISHMENT_CODE", "001")
        codigo_punto_emision = codigo_punto_emision or os.getenv("EMITTER_EMISSION_POINT_CODE", "001")
        ambiente = ambiente or os.getenv("SRI_ENVIRONMENT", "TEST")
        obligado_contabilidad = obligado_contabilidad or os.getenv("EMITTER_OBLIGADO_CONTABILIDAD", "NO")

        if not ruc_emisor:
            return {"success": False, "error": "RUC del emisor no configurado. Pásalo como parámetro o configura EMITTER_RUC en .env"}

        # Parsear fecha (default: hoy)
        if not fecha_emision:
            dt = datetime.now()
        else:
            try:
                if "-" in fecha_emision and len(fecha_emision) == 10:
                    dt = datetime.strptime(fecha_emision, "%Y-%m-%d")
                elif "/" in fecha_emision:
                    dt = datetime.strptime(fecha_emision, "%d/%m/%Y")
                else:
                    dt = datetime.now()
            except Exception:
                dt = datetime.now()

        # Generar clave de acceso
        environment = "PRODUCTION" if str(ambiente).upper().startswith("PROD") else "TEST"
        sequential_str = secuencial.zfill(9)

        access_key = generate_access_key(
            issue_date=dt,
            doc_type="01",
            ruc=ruc_emisor,
            environment=environment,
            establishment=codigo_establecimiento.zfill(3),
            emission_point=codigo_punto_emision.zfill(3),
            sequential=sequential_str,
        )

        # Calcular totales
        subtotal = 0.0
        total_discount = 0.0
        for item in items:
            qty = float(item.get("quantity", 1))
            price = float(item.get("unitPrice", 0))
            disc = float(item.get("discount", 0))
            subtotal += (qty * price)
            total_discount += disc

        base_imponible = subtotal - total_discount
        iva_value = base_imponible * 0.15
        total = base_imponible + iva_value

        # Construir datos de factura
        invoice_data = {
            "accessKey": access_key,
            "establishmentCode": codigo_establecimiento.zfill(3),
            "emissionPointCode": codigo_punto_emision.zfill(3),
            "sequential": sequential_str,
            "issueDate": dt.strftime("%d/%m/%Y"),
            "subtotal": subtotal,
            "totalDiscount": total_discount,
            "ivaValue": iva_value,
            "total": total,
            "paymentMethod": forma_pago,
            "customer": {
                "identificationType": tipo_identificacion_comprador,
                "identification": identificacion_comprador,
                "businessName": razon_social_comprador,
                "email": email_comprador,
                "address": direccion_comprador or None,
                "phone": telefono_comprador or None,
            },
            "items": items,
        }

        company_data = {
            "ruc": ruc_emisor,
            "businessName": razon_social_emisor,
            "tradeName": nombre_comercial_emisor,
            "address": direccion_emisor,
            "environment": environment,
            "obligadoContabilidad": obligado_contabilidad,
        }

        xml_content = generate_invoice_xml(invoice_data, company_data)
        formatted_number = f"{codigo_establecimiento.zfill(3)}-{codigo_punto_emision.zfill(3)}-{sequential_str}"

        return {
            "success": True,
            "xml_content": xml_content,
            "access_key": access_key,
            "formatted_number": formatted_number,
            "totals": {
                "subtotal": f"{subtotal:.2f}",
                "total_discount": f"{total_discount:.2f}",
                "base_imponible": f"{base_imponible:.2f}",
                "iva_15_percent": f"{iva_value:.2f}",
                "total": f"{total:.2f}",
            },
        }

    except Exception as e:
        logger.error(f"❌ Error generando XML: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool()
def firmar_xml(
    xml_content: str,
    certificate_path: str = "",
    certificate_password: str = "",
) -> dict:
    """⚠️ MUTATION — Digitally sign an XML with XAdES-BES using a PKCS#12 certificate.

    Uses the Java signing microservice (Apache Santuario / Bouncy Castle) configured
    at SIGNING_SERVICE_URL env var (default: http://localhost:18081).

    REQUIRED PARAMETERS:
      xml_content (str): Unsigned XML content from generar_factura_xml().

    OPTIONAL PARAMETERS:
      certificate_path (str): Path to .p12 certificate file.
                               Falls back to CERTIFICATE_PATH env var.
      certificate_password (str): Certificate password.
                                   Falls back to CERTIFICATE_PASSWORD env var.

    RETURNS:
      {"success": True, "signed_xml": "<factura...><Signature...>",
       "certificate_info": {"subject", "issuer", "serial_number", "valid_from", "valid_to"}}

    EXAMPLE CALL:
      firmar_xml(xml_content="<factura...>")  # cert from env vars
    """
    try:
        # Usar valores del .env si no se proporcionan
        p12_path = certificate_path or os.getenv("CERTIFICATE_PATH", "")
        p12_pass = certificate_password or os.getenv("CERTIFICATE_PASSWORD", "")
        
        java_service_url = os.getenv("SIGNING_SERVICE_URL", "http://localhost:18081")

        if not p12_path:
            return {"success": False, "error": "No se especificó ruta del certificado (.p12). Configure CERTIFICATE_PATH en .env"}
        if not p12_pass:
            return {"success": False, "error": "No se especificó contraseña del certificado. Configure CERTIFICATE_PASSWORD en .env"}
        if not os.path.exists(p12_path):
            return {"success": False, "error": f"Archivo de certificado no encontrado: {p12_path}"}

        # Firmar usando el microservicio Java (Santuario / BouncyCastle)
        with open(p12_path, "rb") as f:
            cert_b64 = base64.b64encode(f.read()).decode()
            
        logger.info("Delegando firma XAdES-BES al microservicio Java...")
        # SECURITY (mcphub-5ub): enviar X-Signing-Key en el header para que el
        # microservicio rechace requests sin autenticación. La clave se lee de
        # SIGNING_API_KEY (debe coincidir con la configurada en el Java service).
        signing_api_key = os.getenv("SIGNING_API_KEY", "")
        headers = {"X-Signing-Key": signing_api_key} if signing_api_key else {}
        resp = httpx.post(
            f"{java_service_url}/api/v1/signature/sign",
            json={
                "xmlContent": xml_content,
                "certificateBase64": cert_b64,
                "certificatePassword": p12_pass
            },
            headers=headers,
            timeout=10.0
        )
        
        if resp.status_code != 200:
            return {"success": False, "error": f"Error del microservicio de firma: {resp.text}"}
            
        data = resp.json()
        if not data.get("success"):
            return {"success": False, "error": f"Error en firma Java: {data.get('errorMessage')}"}
            
        signed_xml = data["signedXml"]

        # Extraer info básica de certificado (opcional, solo para metadatos MCP)
        try:
            _, cert, _ = _load_p12(p12_path, p12_pass)
            cert_info = {
                "subject": str(cert.subject),
                "issuer": str(cert.issuer),
                "serial_number": str(cert.serial_number),
                "valid_from": cert.not_valid_before_utc.isoformat(),
                "valid_to": cert.not_valid_after_utc.isoformat(),
            }
        except Exception as e:
            logger.warning(f"No se pudo extraer metadata del certificado localmente: {e}")
            cert_info = {}

        return {
            "success": True,
            "signed_xml": signed_xml,
            "certificate_info": cert_info,
        }

    except Exception as e:
        logger.error(f"❌ Error firmando XML: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool()
def enviar_al_sri(
    xml_content: str,
    ambiente: str = "",
) -> dict:
    """⚠️ MUTATION — Submit a signed electronic document to the SRI for reception validation.

    Uses SOAP service: RecepcionComprobantesOffline.
    The XML MUST be digitally signed before submission (use firmar_xml first).

    REQUIRED PARAMETERS:
      xml_content (str): Signed XML document (output from firmar_xml).

    OPTIONAL PARAMETERS:
      ambiente (str): SRI environment. Valid values: "TEST" | "PRODUCTION"
                      Falls back to SRI_ENVIRONMENT env var.
                      WARNING: PRODUCTION is legally binding and irreversible.

    RETURNS:
      {"success": True/False, "claveAcceso": "49 digits",
       "estado": "RECIBIDA" | "DEVUELTA",
       "mensajes": [{"identificador", "mensaje", "informacionAdicional", "tipo"}]}

    SOAP URLs:
      TEST:       https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline
      PRODUCTION: https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline
    """
    try:
        ambiente_final = str(ambiente or os.getenv("SRI_ENVIRONMENT", "TEST")).upper()
        environment = "PRODUCTION" if ambiente_final.startswith("PROD") else "TEST"
        result = send_invoice_to_sri(xml_content, environment)
        return result
    except Exception as e:
        logger.error(f"❌ Error enviando al SRI: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool()
def consultar_autorizacion(
    clave_acceso: str,
    ambiente: str = "",
) -> dict:
    """Check the authorization status of an electronic document in the SRI.

    Uses SOAP service: AutorizacionComprobantesOffline. The access key must be exactly
    49 digits (obtained from generar_factura_xml or from a previous emission).

    REQUIRED PARAMETERS:
      clave_acceso (str): 49-digit SRI access key.
                          Example: "0107202501179001691900011000000017456789011"

    OPTIONAL PARAMETERS:
      ambiente (str): SRI environment. Valid values: "TEST" | "PRODUCTION"
                      Falls back to SRI_ENVIRONMENT env var.

    RETURNS:
      {"estado": "AUTORIZADO" | "NO_AUTORIZADO" | "RECHAZADA",
       "numeroAutorizacion": "49-digit number",
       "fechaAutorizacion": "ISO datetime",
       "ambiente": "PRUEBAS" | "PRODUCCION",
       "mensajes": [{"identificador", "mensaje", "informacionAdicional", "tipo"}]}

    SOAP URLs:
      TEST:       https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline
      PRODUCTION: https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline
    """
    try:
        ambiente_final = str(ambiente or os.getenv("SRI_ENVIRONMENT", "TEST")).upper()
        environment = "PRODUCTION" if ambiente_final.startswith("PROD") else "TEST"
        result = check_authorization_sri(clave_acceso, environment)
        return result
    except Exception as e:
        logger.error(f"❌ Error consultando autorización: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool()
def flujo_completo_factura(
    secuencial: str,
    tipo_identificacion_comprador: str,
    identificacion_comprador: str,
    razon_social_comprador: str,
    email_comprador: str,
    items: list[dict],
    fecha_emision: str = "",
    forma_pago: str = "01",
    direccion_comprador: str = "",
    telefono_comprador: str = "",
    ruc_emisor: str = "",
    razon_social_emisor: str = "",
    nombre_comercial_emisor: str = "",
    direccion_emisor: str = "",
    codigo_establecimiento: str = "",
    codigo_punto_emision: str = "",
    ambiente: str = "",
    obligado_contabilidad: str = "",
    certificate_path: str = "",
    certificate_password: str = "",
    espera_autorizacion: int = 5,
    intentos_autorizacion: int = 5,
) -> dict:
    """⚠️ MUTATION — Execute the complete electronic billing workflow in a single call.

    Runs all 4 steps sequentially:
      Step 1: generar_factura_xml() — Build SRI-compliant XML
      Step 2: firmar_xml() — Sign with XAdES-BES using .p12 certificate
      Step 3: enviar_al_sri() — Submit via SOAP (RecepcionComprobantesOffline)
      Step 4: consultar_autorizacion() — Poll for authorization (AutorizacionComprobantesOffline)

    PREFER this tool over calling each step individually.
    Emitter and certificate data are auto-loaded from env vars if not provided.

    REQUIRED PARAMETERS:
      secuencial (str): Invoice sequential number. Example: "25"
      tipo_identificacion_comprador (str): "CEDULA" | "RUC" | "PASAPORTE" | "CONSUMIDOR_FINAL"
      identificacion_comprador (str): Buyer ID. Example: "0912345678"
      razon_social_comprador (str): Buyer name. Example: "Juan Perez"
      email_comprador (str): Buyer email address.
      items (list[dict]): Invoice items. Each requires:
                          {"mainCode": "X", "description": "Y",
                           "quantity": 1, "unitPrice": 10.0, "discount": 0}

    OPTIONAL PARAMETERS:
      fecha_emision (str): Issue date YYYY-MM-DD. Default: today.
      forma_pago (str): SRI payment code. "01"=Cash (default), "19"=Credit card, "20"=Transfer.
      direccion_comprador (str): Buyer address.
      telefono_comprador (str): Buyer phone.
      ruc_emisor, razon_social_emisor, nombre_comercial_emisor, direccion_emisor (str):
        Emitter data. All fall back to env vars: EMITTER_RUC, EMITTER_BUSINESS_NAME, etc.
      codigo_establecimiento (str): 3-digit establishment code. Default "001".
      codigo_punto_emision (str): 3-digit emission point code. Default "001".
      ambiente (str): "TEST" | "PRODUCTION". Default from SRI_ENVIRONMENT env var.
      obligado_contabilidad (str): "SI" | "NO". Default from env var.
      certificate_path (str): Path to .p12 file. Falls back to CERTIFICATE_PATH env var.
      certificate_password (str): Certificate password. Falls back to CERTIFICATE_PASSWORD env var.
      espera_autorizacion (int, default=5): Seconds to wait between authorization polls.
      intentos_autorizacion (int, default=5): Maximum authorization poll attempts.

    RETURNS:
      {"step_1_generate_xml": {...}, "step_2_sign_xml": {...},
       "step_3_send_to_sri": {...}, "step_4_authorization": {...},
       "final_status": "AUTORIZADO" | "ERROR" | "DEVUELTA" | "TIMEOUT_AUTORIZACION",
       "access_key": "49 digits", "authorization_number": "49 digits"}

    EXAMPLE CALL:
      flujo_completo_factura(secuencial="1",
                             tipo_identificacion_comprador="CONSUMIDOR_FINAL",
                             identificacion_comprador="9999999999999",
                             razon_social_comprador="CONSUMIDOR FINAL",
                             email_comprador="cliente@test.com",
                             items=[{"mainCode": "SRV-001", "description": "Service",
                                     "quantity": 1, "unitPrice": 100.0, "discount": 0}])
    """
    workflow_result = {
        "step_1_generate_xml": None,
        "step_2_sign_xml": None,
        "step_3_send_to_sri": None,
        "step_4_authorization": None,
        "final_status": "ERROR",
        "access_key": None,
        "authorization_number": None,
    }

    try:
        # === PASO 1: Generar XML ===
        logger.info("📋 PASO 1/4: Generando XML de factura...")
        xml_result = generar_factura_xml(
            ruc_emisor=ruc_emisor,
            razon_social_emisor=razon_social_emisor,
            nombre_comercial_emisor=nombre_comercial_emisor,
            direccion_emisor=direccion_emisor,
            codigo_establecimiento=codigo_establecimiento,
            codigo_punto_emision=codigo_punto_emision,
            secuencial=secuencial,
            fecha_emision=fecha_emision,
            tipo_identificacion_comprador=tipo_identificacion_comprador,
            identificacion_comprador=identificacion_comprador,
            razon_social_comprador=razon_social_comprador,
            email_comprador=email_comprador,
            items=items,
            ambiente=ambiente,
            obligado_contabilidad=obligado_contabilidad,
            forma_pago=forma_pago,
            direccion_comprador=direccion_comprador,
            telefono_comprador=telefono_comprador,
        )

        workflow_result["step_1_generate_xml"] = {
            "success": xml_result["success"],
            "access_key": xml_result.get("access_key"),
            "formatted_number": xml_result.get("formatted_number"),
            "totals": xml_result.get("totals"),
        }

        if not xml_result["success"]:
            workflow_result["final_status"] = "ERROR_GENERAR_XML"
            return workflow_result

        access_key = xml_result["access_key"]
        xml_content = xml_result["xml_content"]
        workflow_result["access_key"] = access_key

        # === PASO 2: Firmar XML ===
        logger.info("🔏 PASO 2/4: Firmando XML con XAdES-BES...")
        sign_result = firmar_xml(
            xml_content=xml_content,
            certificate_path=certificate_path,
            certificate_password=certificate_password,
        )

        workflow_result["step_2_sign_xml"] = {
            "success": sign_result["success"],
            "certificate_info": sign_result.get("certificate_info"),
            "error": sign_result.get("error"),
        }

        if not sign_result["success"]:
            workflow_result["final_status"] = "ERROR_FIRMA"
            return workflow_result

        signed_xml = sign_result["signed_xml"]

        # === PASO 3: Enviar al SRI ===
        logger.info("📤 PASO 3/4: Enviando al SRI...")
        send_result = enviar_al_sri(
            xml_content=signed_xml,
            ambiente=ambiente,
        )

        workflow_result["step_3_send_to_sri"] = send_result

        if not send_result.get("success"):
            workflow_result["final_status"] = "ERROR_ENVIO" if "error" in send_result else "DEVUELTA"
            return workflow_result

        # === PASO 4: Consultar Autorización ===
        logger.info(f"⏳ PASO 4/4: Consultando autorización (máximo {intentos_autorizacion} intentos)...")

        for i in range(intentos_autorizacion):
            time.sleep(espera_autorizacion)
            logger.info(f"🔄 Intento {i + 1}/{intentos_autorizacion} de consulta de autorización...")

            auth_result = consultar_autorizacion(
                clave_acceso=access_key,
                ambiente=ambiente,
            )

            estado = auth_result.get("estado", "DESCONOCIDO")

            if estado == "AUTORIZADO":
                logger.info(f"✅ Comprobante AUTORIZADO: {auth_result.get('numeroAutorizacion')}")
                workflow_result["step_4_authorization"] = auth_result
                workflow_result["final_status"] = "AUTORIZADO"
                workflow_result["authorization_number"] = auth_result.get("numeroAutorizacion")
                return workflow_result

            if estado in ("NO_AUTORIZADO", "RECHAZADA"):
                logger.error(f"❌ Comprobante RECHAZADO/NO_AUTORIZADO")
                workflow_result["step_4_authorization"] = auth_result
                workflow_result["final_status"] = estado
                return workflow_result

        # Se agotaron los intentos
        workflow_result["step_4_authorization"] = {"estado": "TIMEOUT", "mensaje": "Se agotó el tiempo de espera"}
        workflow_result["final_status"] = "TIMEOUT_AUTORIZACION"
        return workflow_result

    except Exception as e:
        logger.error(f"❌ Error en flujo completo: {e}")
        workflow_result["final_status"] = "ERROR"
        workflow_result["error"] = str(e)
        return workflow_result


@mcp.tool()
def validar_certificado(
    certificate_path: str = "",
    certificate_password: str = "",
) -> dict:
    """Validate a PKCS#12 (.p12) digital certificate and display its information.

    Useful to verify certificate validity before signing invoices.

    OPTIONAL PARAMETERS:
      certificate_path (str): Path to .p12 file. Falls back to CERTIFICATE_PATH env var.
      certificate_password (str): Certificate password. Falls back to CERTIFICATE_PASSWORD env var.

    RETURNS:
      {"success": True,
       "certificate_info": {"subject", "issuer", "serial_number",
                             "valid_from", "valid_to",
                             "is_currently_valid": bool,
                             "days_remaining": int,
                             "key_type": "RSAPrivateKey",
                             "additional_certs_count": int}}
    """
    try:
        p12_path = certificate_path or os.getenv("CERTIFICATE_PATH", "")
        p12_pass = certificate_password or os.getenv("CERTIFICATE_PASSWORD", "")
        

        if not p12_path:
            return {"success": False, "error": "No se especificó ruta del certificado"}
        if not p12_pass:
            return {"success": False, "error": "No se especificó contraseña del certificado"}
        if not os.path.exists(p12_path):
            return {"success": False, "error": f"Archivo no encontrado: {p12_path}"}

        private_key, cert, ca_certs = _load_p12(p12_path, p12_pass)

        now = datetime.now(timezone.utc)
        is_valid = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
        days_remaining = (cert.not_valid_after_utc - now).days

        return {
            "success": True,
            "certificate_info": {
                "subject": str(cert.subject),
                "issuer": str(cert.issuer),
                "serial_number": str(cert.serial_number),
                "valid_from": cert.not_valid_before_utc.isoformat(),
                "valid_to": cert.not_valid_after_utc.isoformat(),
                "is_currently_valid": is_valid,
                "days_remaining": days_remaining,
                "key_type": type(private_key).__name__,
                "additional_certs_count": len(ca_certs),
            },
        }

    except Exception as e:
        logger.error(f"❌ Error validando certificado: {e}")
        return {"success": False, "error": str(e)}


@mcp.tool()
def validar_clave_acceso(
    clave_acceso: str,
) -> dict:
    """Validate the structure and check digit of an SRI access key.

    Access key format (49 digits):
    DDMMYYYY(8) + DocType(2) + RUC(13) + Environment(1) + Series(6) + Sequential(9) + NumericCode(8) + EmissionType(1) + CheckDigit(1)

    REQUIRED PARAMETERS:
      clave_acceso (str): 49-digit access key to validate.
                          Example: "0107202501179001691900011000000017456789011"

    RETURNS:
      {"valid": True/False,
       "components": {"fecha": "DD/MM/YYYY", "tipo_comprobante": "01",
                       "tipo_comprobante_nombre": "Factura", "ruc": "13 digits",
                       "ambiente": "Pruebas" | "Produccion",
                       "establecimiento": "001", "punto_emision": "001",
                       "secuencial": "9 digits", "codigo_numerico": "8 digits",
                       "tipo_emision": "1", "digito_verificador": "1"}}

    DOC TYPES: '01'=Invoice, '04'=Credit note, '05'=Debit note,
               '06'=Waybill, '07'=Retention.
    """
    if not clave_acceso or not clave_acceso.isdigit():
        return {"valid": False, "error": "La clave de acceso debe contener solo dígitos"}

    if len(clave_acceso) != 49:
        return {"valid": False, "error": f"La clave debe tener 49 dígitos, tiene {len(clave_acceso)}"}

    is_valid = validate_access_key(clave_acceso)

    # Desglosar componentes
    components = {
        "fecha": f"{clave_acceso[0:2]}/{clave_acceso[2:4]}/{clave_acceso[4:8]}",
        "tipo_comprobante": clave_acceso[8:10],
        "ruc": clave_acceso[10:23],
        "ambiente": "Pruebas" if clave_acceso[23] == "1" else "Producción",
        "establecimiento": clave_acceso[24:27],
        "punto_emision": clave_acceso[27:30],
        "secuencial": clave_acceso[30:39],
        "codigo_numerico": clave_acceso[39:47],
        "tipo_emision": clave_acceso[47],
        "digito_verificador": clave_acceso[48],
    }

    doc_types = {"01": "Factura", "04": "Nota de Crédito", "05": "Nota de Débito", "06": "Guía de Remisión", "07": "Comprobante de Retención"}
    components["tipo_comprobante_nombre"] = doc_types.get(components["tipo_comprobante"], "Desconocido")

    return {
        "valid": is_valid,
        "components": components,
    }


@mcp.tool()
def consultar_informacion_ruc(
    ruc: str,
) -> dict:
    """Read a taxpayer's general information directly from the SRI public registry.

    This tool makes a direct HTTP query to the SRI public taxpayer census endpoint
    to fetch real-time information about a given RUC, such as the registered name,
    business activity, accounting status, authorized representatives, etc.
    No authentication is required.

    REQUIRED PARAMETERS:
      ruc (str): 13-digit RUC to check. Example: "1790016919001"

    RETURNS:
      {"success": True/False,
       "data": [{"numeroRuc": "...", "razonSocial": "...", "estadoContribuyenteRuc": "...", ...}],
       "error": "..." (if success is False)}

    EXAMPLE CALL:
      consultar_informacion_ruc(ruc="0993396918001")
    """
    if not ruc or not ruc.isdigit() or len(ruc) != 13:
        return {"success": False, "error": "El RUC debe contener exactamente 13 dígitos numéricos."}

    import urllib.request
    import json
    import urllib.error

    try:
        url = f"https://srienlinea.sri.gob.ec/sri-catastro-sujeto-servicio-internet/rest/ConsolidadoContribuyente/obtenerPorNumerosRuc?&ruc={ruc}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Content-Type": "application/json; charset=UTF-8"
            }
        )
        
        # Timeout configured to 15 seconds to avoid blocking indefinitely
        res = urllib.request.urlopen(req, timeout=15)  # nosec B310
        response_data = res.read().decode("utf-8")
        
        if not response_data:
            return {"success": False, "error": "El SRI no devolvió datos (posiblemente RUC inválido o inactivo)."}
            
        json_data = json.loads(response_data)
        
        return {
            "success": True,
            "data": json_data
        }
        
    except urllib.error.HTTPError as e:
        logger.error(f"❌ Error HTTP consultando RUC {ruc} en SRI: {e}")
        return {"success": False, "error": f"Error HTTP del SRI: {e.code} - {e.reason}"}
    except Exception as e:
        logger.error(f"❌ Error consultando RUC {ruc} en SRI: {e}")
        return {"success": False, "error": f"Error de conexión o parseo: {str(e)}"}


# ==============================================================================
# Expansión de Herramientas Utilitarias (SRI / Contabilidad / Nómina)
# ==============================================================================

from schemas.sri_models import TipoContribuyente, AtsRequest
from services.taxes import calcular_retencion_renta, calcular_rol_pagos
from services.xml_parser import parsear_xml_sri, generar_estructura_ats
from services.validation import analizar_identificacion_y_plazos, verificar_estado_tributario, consultar_estado_sri
from services.pdf_generator import generar_pdf_ride

@mcp.tool()
def calcular_retencion_mcp(
    tipo_contribuyente_emisor: str,
    tipo_contribuyente_receptor: str,
    codigo_concepto: str,
    monto_base: float
) -> dict:
    """
    Calcula los porcentajes y valores de retención en la fuente e IVA.
    
    REQUIRED PARAMETERS:
      tipo_contribuyente_emisor (str): "PERSONA_NATURAL", "SOCIEDAD", "CONTRIBUYENTE_ESPECIAL", "ENTIDAD_PUBLICA"
      tipo_contribuyente_receptor (str): "PERSONA_NATURAL", "SOCIEDAD", "CONTRIBUYENTE_ESPECIAL", "ENTIDAD_PUBLICA"
      codigo_concepto (str): Ej: "312", "303", "343"
      monto_base (float): Base imponible sobre la cual calcular la retención.
    """
    try:
        emisor = TipoContribuyente(tipo_contribuyente_emisor)
        receptor = TipoContribuyente(tipo_contribuyente_receptor)
        return calcular_retencion_renta(emisor, receptor, codigo_concepto, monto_base)
    except ValueError as e:
        return {"error": str(e)}

@mcp.tool()
def calcular_rol_pagos_mcp(
    sueldo_base: float,
    dias_trabajados: int = 30,
    horas_extras: float = 0.0
) -> dict:
    """
    Calcula determinísticamente un rol de pagos básico.
    
    REQUIRED PARAMETERS:
      sueldo_base (float): Sueldo base mensual del trabajador.
      dias_trabajados (int): Número de días trabajados en el mes (default 30).
      horas_extras (float): Valor de horas extras ganadas en el mes.
    """
    return calcular_rol_pagos(sueldo_base, dias_trabajados, horas_extras)

@mcp.tool()
def parsear_xml_sri_mcp(xml_crudo: str) -> dict:
    """
    Parsea una factura electrónica del SRI (XML) y extrae información relevante sin enviar el XML completo al LLM.
    
    REQUIRED PARAMETERS:
      xml_crudo (str): Contenido XML de la factura electrónica.
    """
    return parsear_xml_sri(xml_crudo)

@mcp.tool()
def generar_estructura_ats_mcp(compras: list, ventas: list) -> str:
    """
    Genera el XML del Anexo Transaccional Simplificado (ATS) en base a listas de transacciones.
    
    REQUIRED PARAMETERS:
      compras (list): Lista de objetos/diccionarios con los detalles de compras.
      ventas (list): Lista de objetos/diccionarios con los detalles de ventas.
    """
    return generar_estructura_ats(compras, ventas)

@mcp.tool()
def analizar_identificacion_y_plazos_mcp(identificacion: str) -> dict:
    """
    Valida una cédula o RUC ecuatoriano e infiere los plazos máximos de declaración según el 9no dígito.
    
    REQUIRED PARAMETERS:
      identificacion (str): Cédula de 10 dígitos o RUC de 13 dígitos.
    """
    return analizar_identificacion_y_plazos(identificacion)

@mcp.tool()
def verificar_estado_tributario_mcp(ruc: str) -> dict:
    """
    Verifica el estado tributario de un RUC (régimen, si es RIMPE, o Agente de Retención).
    
    REQUIRED PARAMETERS:
      ruc (str): RUC de 13 dígitos.
    """
    return verificar_estado_tributario(ruc)

@mcp.tool()
def consultar_estado_sri_mcp(ambiente: str = "pruebas") -> dict:
    """
    Realiza un ping a los servidores del SRI para verificar si el web service está online.
    
    REQUIRED PARAMETERS:
      ambiente (str): "pruebas" o "produccion".
    """
    return consultar_estado_sri(ambiente)

@mcp.tool()
def generar_pdf_ride_mcp(xml_factura: str) -> str:
    """
    Genera un PDF RIDE base64 inyectando los datos de la factura XML proporcionada.
    
    REQUIRED PARAMETERS:
      xml_factura (str): Contenido XML de la factura electrónica.
    """
    return generar_pdf_ride(xml_factura)


# ==============================================================================
# Punto de entrada
# ==============================================================================

def main():
    """Inicia el servidor MCP."""
    import uvicorn

    port = int(os.getenv("MCP_PORT", "8002"))
    host = os.getenv("MCP_HOST", "0.0.0.0")
    transport_mode = os.getenv("MCP_TRANSPORT_MODE", "sse").lower()

    logger.info(f"🚀 Iniciando SRI MCP Server en http://{host}:{port}/mcp")
    logger.info(f"📋 Ambiente SRI: {os.getenv('SRI_ENVIRONMENT', 'TEST')}")
    logger.info(f"🔐 Certificado: {os.getenv('CERTIFICATE_PATH', 'No configurado')}")

    if transport_mode == "sse":
        app = mcp.sse_app()
    elif transport_mode == "http_stream":
        app = mcp.streamable_http_app()
    else:
        raise ValueError(f"Unknown transport mode: {transport_mode}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
