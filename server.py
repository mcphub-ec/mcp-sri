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


# ==============================================================================
# Módulo 1: Generación de Clave de Acceso (access-key.service.ts)
# ==============================================================================

def _calculate_module11(key: str) -> str:
    """
    Calcula el dígito verificador usando módulo 11.
    Replica EXACTAMENTE la lógica de access-key.service.ts:
    - Recorre de derecha a izquierda
    - Factor: 2,3,4,5,6,7,2,3,...
    - checkDigit = 11 - (sum % 11)
    - Si result == 11 → '0'
    - Si result == 10 → '1' (implícito en la lógica original: mod==0 → 0)
    """
    total = 0
    factor = 2
    for ch in reversed(key):
        total += int(ch) * factor
        factor = 2 if factor == 7 else factor + 1

    mod = total % 11
    check = 0 if mod == 0 else 11 - mod
    return "0" if check == 11 else str(check)


def generate_access_key(
    issue_date: datetime,
    doc_type: str,
    ruc: str,
    environment: str,
    establishment: str,
    emission_point: str,
    sequential: str,
) -> str:
    """
    Genera la clave de acceso de 49 dígitos según normativa SRI.
    Formato: DDMMAAAA TT RRRRRRRRRRRRR A EEE PPP NNNNNNNNN CCCCCCCC T D
    (8+2+13+1+3+3+9+8+1 = 48 + 1 dígito verificador = 49)

    Réplica exacta de access-key.service.ts
    """
    # Fecha DDMMAAAA
    date_str = issue_date.strftime("%d%m%Y")

    # Tipo documento (2 dígitos)
    doc_type_str = doc_type.zfill(2)

    # RUC (13 dígitos)
    ruc_str = ruc.zfill(13)

    # Ambiente (1=Pruebas, 2=Producción)
    env = "2" if environment == "PRODUCTION" else "1"

    # Serie (establecimiento + punto emisión = 6 dígitos)
    serie = establishment.zfill(3) + emission_point.zfill(3)

    # Secuencial (9 dígitos)
    seq = sequential.zfill(9)

    # Código numérico (8 dígitos exactos, entre 10000000 y 99999999)
    numeric_code = str(random.randint(10000000, 99999999))

    # Tipo de emisión (1=Normal)
    emission_type = "1"

    # Base de 48 dígitos
    base48 = date_str + doc_type_str + ruc_str + env + serie + seq + numeric_code + emission_type

    if len(base48) != 48:
        raise ValueError(f"Error: clave base debe tener 48 dígitos, tiene {len(base48)}")

    # Dígito verificador
    check_digit = _calculate_module11(base48)

    full_key = base48 + check_digit
    logger.info(f"🔑 Clave de acceso generada: {full_key} (longitud: {len(full_key)})")
    return full_key


def validate_access_key(access_key: str) -> bool:
    """Valida una clave de acceso verificando el dígito de control."""
    if len(access_key) != 49:
        return False
    base48 = access_key[:48]
    check_digit = access_key[48]
    return check_digit == _calculate_module11(base48)


# ==============================================================================
# Módulo 2: Generación de XML Factura (xml-generator.service.ts)
# ==============================================================================

def _map_identification_type(id_type: str) -> str:
    """Mapea tipo de identificación al código SRI."""
    return ID_TYPE_MAP.get(id_type, "07")


def _normalize_identification(identification: str, id_type: str) -> str:
    """Normaliza identificación - consumidor final = 9999999999999."""
    if id_type in ("CONSUMIDOR_FINAL", "07"):
        return "9999999999999"
    return identification


def generate_invoice_xml(invoice_data: dict, company_data: dict) -> str:
    """
    Genera el XML de una factura según esquema SRI.
    Estructura EXACTA replicada de xml-generator.service.ts del repositorio de referencia.

    La versión del esquema usada es '2.1.0' (version attribute en <factura>).
    El atributo id='comprobante' es OBLIGATORIO para la referencia de firma.
    """
    # Raíz del documento: <factura id="comprobante" version="2.1.0">
    root = etree.Element("factura", id="comprobante", version="2.1.0")

    # ==================== INFO TRIBUTARIA ====================
    info_tributaria = etree.SubElement(root, "infoTributaria")

    ambiente = "2" if company_data.get("environment") == "PRODUCTION" else "1"
    _txt(info_tributaria, "ambiente", ambiente)
    _txt(info_tributaria, "tipoEmision", "1")  # 1 = Normal
    _txt(info_tributaria, "razonSocial", company_data["businessName"])
    _txt(info_tributaria, "nombreComercial", company_data.get("tradeName", company_data["businessName"]))
    _txt(info_tributaria, "ruc", company_data["ruc"])
    _txt(info_tributaria, "claveAcceso", invoice_data["accessKey"])
    _txt(info_tributaria, "codDoc", "01")  # 01 = Factura
    _txt(info_tributaria, "estab", invoice_data["establishmentCode"])
    _txt(info_tributaria, "ptoEmi", invoice_data["emissionPointCode"])
    _txt(info_tributaria, "secuencial", invoice_data["sequential"])
    _txt(info_tributaria, "dirMatriz", company_data["address"])

    # ==================== INFO FACTURA ====================
    info_factura = etree.SubElement(root, "infoFactura")

    # Fecha de emisión DD/MM/YYYY
    issue_date = invoice_data.get("issueDate", datetime.now().strftime("%d/%m/%Y"))
    if isinstance(issue_date, datetime):
        issue_date = issue_date.strftime("%d/%m/%Y")
    elif "T" in str(issue_date) or "-" in str(issue_date):
        # Convertir de ISO a DD/MM/YYYY
        try:
            dt = datetime.fromisoformat(str(issue_date).replace("Z", "+00:00"))
            issue_date = dt.strftime("%d/%m/%Y")
        except Exception:
            pass

    _txt(info_factura, "fechaEmision", issue_date)
    _txt(info_factura, "dirEstablecimiento", company_data["address"])

    # Obligado a llevar contabilidad
    obligado = company_data.get("obligadoContabilidad", "SI")
    _txt(info_factura, "obligadoContabilidad", obligado)

    # Comprador
    customer = invoice_data.get("customer", {})
    tipo_id_code = _map_identification_type(customer.get("identificationType", "CONSUMIDOR_FINAL"))
    id_normalizada = _normalize_identification(
        customer.get("identification", "9999999999999"),
        customer.get("identificationType", "CONSUMIDOR_FINAL"),
    )

    _txt(info_factura, "tipoIdentificacionComprador", tipo_id_code)

    razon_social_comprador = (
        customer.get("businessName")
        or f'{customer.get("firstName", "")} {customer.get("lastName", "")}'.strip()
        or "CONSUMIDOR FINAL"
    )
    _txt(info_factura, "razonSocialComprador", razon_social_comprador)
    _txt(info_factura, "identificacionComprador", id_normalizada)

    # Dirección comprador (opcional)
    if customer.get("address"):
        _txt(info_factura, "direccionComprador", customer["address"])

    # Calcular totales
    items = invoice_data.get("items", [])
    subtotal_sin_impuestos = 0.0
    total_descuento = 0.0
    iva_total = 0.0

    for item in items:
        qty = float(item.get("quantity", 1))
        price = float(item.get("unitPrice", 0))
        discount = float(item.get("discount", 0))
        item_total = (qty * price) - discount
        subtotal_sin_impuestos += item_total
        total_descuento += discount
        iva_total += item_total * 0.15

    total = subtotal_sin_impuestos + iva_total

    # Usar valores precalculados si vienen en invoice_data (más precisos)
    subtotal_sin_impuestos = float(invoice_data.get("subtotal", subtotal_sin_impuestos))
    total_descuento_val = float(invoice_data.get("totalDiscount", total_descuento))
    subtotal_sin_impuestos = subtotal_sin_impuestos - total_descuento_val
    iva_total = float(invoice_data.get("ivaValue", iva_total))
    total = float(invoice_data.get("total", total))

    _txt(info_factura, "totalSinImpuestos", f"{subtotal_sin_impuestos:.2f}")
    _txt(info_factura, "totalDescuento", f"{total_descuento_val:.2f}")

    # ==================== TOTAL CON IMPUESTOS ====================
    total_con_impuestos = etree.SubElement(info_factura, "totalConImpuestos")

    if subtotal_sin_impuestos > 0:
        total_impuesto = etree.SubElement(total_con_impuestos, "totalImpuesto")
        _txt(total_impuesto, "codigo", "2")          # 2 = IVA
        _txt(total_impuesto, "codigoPorcentaje", "4")  # 4 = 15%
        _txt(total_impuesto, "baseImponible", f"{subtotal_sin_impuestos:.2f}")
        _txt(total_impuesto, "valor", f"{iva_total:.2f}")

    _txt(info_factura, "propina", "0.00")
    _txt(info_factura, "importeTotal", f"{total:.2f}")
    _txt(info_factura, "moneda", "DOLAR")

    # ==================== FORMA DE PAGO ====================
    pagos = etree.SubElement(info_factura, "pagos")
    pago = etree.SubElement(pagos, "pago")
    _txt(pago, "formaPago", invoice_data.get("paymentMethod", "01"))
    _txt(pago, "total", f"{total:.2f}")
    _txt(pago, "plazo", "0")
    _txt(pago, "unidadTiempo", "dias")

    # ==================== DETALLES ====================
    detalles = etree.SubElement(root, "detalles")

    for item in items:
        detalle = etree.SubElement(detalles, "detalle")
        main_code = item.get("mainCode", "PROD-001")

        _txt(detalle, "codigoPrincipal", main_code)
        _txt(detalle, "codigoAuxiliar", main_code)
        _txt(detalle, "descripcion", item.get("description", "Producto"))

        qty = float(item.get("quantity", 1))
        price = float(item.get("unitPrice", 0))
        discount = float(item.get("discount", 0))

        _txt(detalle, "cantidad", f"{qty:.2f}")
        _txt(detalle, "precioUnitario", f"{price:.6f}")
        _txt(detalle, "descuento", f"{discount:.2f}")

        precio_total = (qty * price) - discount
        _txt(detalle, "precioTotalSinImpuesto", f"{precio_total:.2f}")

        # Impuestos del item
        impuestos = etree.SubElement(detalle, "impuestos")
        impuesto = etree.SubElement(impuestos, "impuesto")
        _txt(impuesto, "codigo", "2")             # IVA
        _txt(impuesto, "codigoPorcentaje", "4")    # 4 = 15%
        _txt(impuesto, "tarifa", "15.00")
        _txt(impuesto, "baseImponible", f"{precio_total:.2f}")

        iva_item = precio_total * 0.15
        _txt(impuesto, "valor", f"{iva_item:.2f}")

    # ==================== INFO ADICIONAL (OPCIONAL) ====================
    info_adicional = etree.SubElement(root, "infoAdicional")
    email = customer.get("email", "N/A")
    campo_email = etree.SubElement(info_adicional, "campoAdicional", nombre="Email")
    campo_email.text = email

    phone = customer.get("phone")
    if phone:
        campo_phone = etree.SubElement(info_adicional, "campoAdicional", nombre="Telefono")
        campo_phone.text = phone

    # Generar XML string
    xml_bytes = etree.tostring(root, xml_declaration=True, encoding="UTF-8", pretty_print=False)
    return xml_bytes.decode("UTF-8")


def _txt(parent: etree._Element, tag: str, text: str) -> etree._Element:
    """Helper para crear sub-elemento con texto."""
    el = etree.SubElement(parent, tag)
    el.text = str(text)
    return el


# ==============================================================================
# Módulo 3: Firma Digital XAdES-BES (Replicación de SignatureService.java)
# ==============================================================================

def _load_p12(p12_path: str, password: str) -> tuple[RSAPrivateKey, Certificate, list[Certificate]]:
    """
    Carga un certificado PKCS#12 (.p12).
    Equivalente a loadKeyStore() + getFirstAlias() del Java.
    """
    with open(p12_path, "rb") as f:
        p12_data = f.read()

    private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
        p12_data, password.encode("utf-8"), default_backend()
    )

    if private_key is None or certificate is None:
        raise ValueError("No se encontró clave privada o certificado en el archivo .p12")

    return private_key, certificate, additional_certs or []


# ==============================================================================
# Módulo 4: Comunicación SOAP con el SRI (sri-web-service.service.ts)
# ==============================================================================

def _get_zeep_client(wsdl_url: str) -> ZeepClient:
    """
    Crea un cliente SOAP (Zeep) a partir de la URL WSDL.
    Equivalente a soap.createClientAsync() del TypeScript.
    """
    transport = Transport(timeout=30, operation_timeout=30)
    return ZeepClient(wsdl_url, transport=transport)


def send_invoice_to_sri(
    xml_content: str,
    environment: str = "TEST",
    max_retries: int = 3,
    retry_delay: float = 2.0,
) -> dict:
    """
    Envía un comprobante electrónico al SRI.
    Réplica de sendInvoice() de sri-web-service.service.ts.

    El SRI espera:
    - Método SOAP: validarComprobante
    - Parámetro: xml (contenido XML en Base64)
    - Respuesta: RespuestaRecepcionComprobante con estado RECIBIDA/DEVUELTA
    """
    env_key = "PRODUCTION" if environment == "PRODUCTION" else "TEST"
    url = SRI_URLS[env_key]["reception"]

    # Extraer clave de acceso del XML
    clave_acceso = _extract_access_key(xml_content)

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"📤 Intento {attempt}/{max_retries} - Enviando comprobante al SRI (clave: {clave_acceso})")

            client = _get_zeep_client(url)

            # Codificar XML en Base64 (exacto como en sri-web-service.service.ts)
            xml_base64 = base64.b64encode(xml_content.encode("utf-8")).decode("utf-8")

            # Llamar a validarComprobante
            result = client.service.validarComprobante(xml=xml_base64)

            # Procesar respuesta
            estado = getattr(result, "estado", "DESCONOCIDO")

            logger.info(f"✅ Comprobante enviado exitosamente en intento {attempt}")

            # Extraer mensajes si los hay
            mensajes = []
            comprobantes = getattr(result, "comprobantes", None)
            if comprobantes:
                comp = getattr(comprobantes, "comprobante", None)
                if comp:
                    comp_list = comp if isinstance(comp, list) else [comp]
                    for c in comp_list:
                        msgs = getattr(c, "mensajes", None)
                        if msgs:
                            msg_list = getattr(msgs, "mensaje", [])
                            if not isinstance(msg_list, list):
                                msg_list = [msg_list]
                            for m in msg_list:
                                mensajes.append({
                                    "identificador": getattr(m, "identificador", ""),
                                    "mensaje": getattr(m, "mensaje", ""),
                                    "informacionAdicional": getattr(m, "informacionAdicional", ""),
                                    "tipo": getattr(m, "tipo", ""),
                                })

            return {
                "success": estado == "RECIBIDA",
                "claveAcceso": clave_acceso,
                "estado": estado,
                "mensajes": mensajes,
            }

        except Exception as e:
            is_network = any(x in str(e) for x in ["ECONNRESET", "ETIMEDOUT", "ENOTFOUND", "ConnectionError", "Timeout"])
            if is_network and attempt < max_retries:
                logger.warning(f"⚠️ Intento {attempt} falló ({e}). Reintentando en {retry_delay}s...")
                time.sleep(retry_delay)
                continue

            logger.error(f"❌ Error en intento {attempt}/{max_retries}: {e}")
            raise RuntimeError(f"Error al enviar al SRI después de {attempt} intentos: {e}")


def check_authorization_sri(
    access_key: str,
    environment: str = "TEST",
    max_retries: int = 3,
    retry_delay: float = 2.0,
) -> dict:
    """
    Consulta la autorización de un comprobante en el SRI.
    Réplica de checkAuthorization() de sri-web-service.service.ts.

    Método SOAP: autorizacionComprobante
    Parámetro: claveAccesoComprobante (string de 49 dígitos)
    """
    if not access_key or len(access_key) != 49:
        raise ValueError(f"Clave de acceso inválida: '{access_key}' (longitud: {len(access_key) if access_key else 0})")

    env_key = "PRODUCTION" if environment == "PRODUCTION" else "TEST"
    url = SRI_URLS[env_key]["authorization"]

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"🔍 Intento {attempt}/{max_retries} - Consultando autorización (clave: {access_key})")

            client = _get_zeep_client(url)

            # Llamar a autorizacionComprobante
            result = client.service.autorizacionComprobante(claveAccesoComprobante=access_key)

            # Procesar respuesta (estructura: RespuestaAutorizacionComprobante.autorizaciones.autorizacion)
            autorizaciones_container = getattr(result, "autorizaciones", None)
            autorizaciones = getattr(autorizaciones_container, "autorizacion", None) if autorizaciones_container else None

            if not autorizaciones:
                return {
                    "estado": "NO_AUTORIZADA",
                    "ambiente": environment,
                    "mensajes": [],
                }

            # Puede ser un solo objeto o una lista
            auth_list = autorizaciones if isinstance(autorizaciones, list) else [autorizaciones]
            auth = auth_list[0]

            logger.info(f"✅ Autorización consultada exitosamente en intento {attempt}")

            # Extraer mensajes
            mensajes = []
            msgs_container = getattr(auth, "mensajes", None)
            if msgs_container:
                msg_list = getattr(msgs_container, "mensaje", [])
                if not isinstance(msg_list, list):
                    msg_list = [msg_list]
                for m in msg_list:
                    mensajes.append({
                        "identificador": getattr(m, "identificador", ""),
                        "mensaje": getattr(m, "mensaje", ""),
                        "informacionAdicional": getattr(m, "informacionAdicional", ""),
                        "tipo": getattr(m, "tipo", ""),
                    })

            return {
                "estado": getattr(auth, "estado", "DESCONOCIDO"),
                "numeroAutorizacion": getattr(auth, "numeroAutorizacion", None),
                "fechaAutorizacion": str(getattr(auth, "fechaAutorizacion", "")),
                "ambiente": getattr(auth, "ambiente", environment),
                "comprobante": getattr(auth, "comprobante", None),
                "mensajes": mensajes,
            }

        except Exception as e:
            is_network = any(x in str(e) for x in ["ConnectionError", "Timeout", "ECONNRESET"])
            if is_network and attempt < max_retries:
                logger.warning(f"⚠️ Intento {attempt} falló ({e}). Reintentando en {retry_delay}s...")
                time.sleep(retry_delay)
                continue

            logger.error(f"❌ Error en intento {attempt}/{max_retries}: {e}")
            raise RuntimeError(f"Error al consultar autorización después de {attempt} intentos: {e}")


def _extract_access_key(xml_content: str) -> str:
    """Extrae la clave de acceso del XML."""
    root = etree.fromstring(xml_content.encode("UTF-8") if isinstance(xml_content, str) else xml_content)
    clave_el = root.find(".//claveAcceso")
    if clave_el is not None and clave_el.text:
        return clave_el.text
    raise ValueError("No se encontró la clave de acceso en el XML")


# ==============================================================================
# Módulo 5: Servidor MCP
# ==============================================================================

mcp = FastMCP(
    "SRI Electronic Billing",
    host=os.getenv("MCP_HOST", "0.0.0.0"),
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
        resp = httpx.post(
            f"{java_service_url}/api/v1/signature/sign",
            json={
                "xmlContent": xml_content,
                "certificateBase64": cert_b64,
                "certificatePassword": p12_pass
            },
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
        res = urllib.request.urlopen(req, timeout=15)
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
