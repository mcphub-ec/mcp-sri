"""Core logic extracted from server.py"""
import os
import random
import uuid
import base64
import hashlib
import time
import httpx
import logging
from datetime import datetime
from io import BytesIO

from lxml import etree
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
from cryptography.hazmat.primitives.hashes import SHA256, SHA1
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate
from zeep import Client as ZeepClient
from zeep.transports import Transport
from zeep.exceptions import Fault as ZeepFault

logger = logging.getLogger("sri-mcp-core")

XADES_NS = "http://uri.etsi.org/01903/v1.3.2#"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

ID_TYPE_MAP = {
    "CEDULA": "05",
    "RUC": "04",
    "PASAPORTE": "06",
    "CONSUMIDOR_FINAL": "07",
    "IDENTIFICACION_EXTERIOR": "08",
}

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


