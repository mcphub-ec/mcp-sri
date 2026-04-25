from lxml import etree
import json

def parsear_xml_sri(xml_crudo: str) -> dict:
    """
    Parsea una factura electrónica del SRI (XML) y extrae la información relevante:
    RUC del proveedor, Razón Social, Fecha, Base 0%, Base 15%, IVA, y Total.
    """
    try:
        # En facturas electrónicas, puede haber un <autorizacion> con un CDATA que contiene el comprobante.
        # Primero intentamos parsear el XML tal cual.
        parser = etree.XMLParser(recover=True)
        root = etree.fromstring(xml_crudo.encode('utf-8'), parser=parser)
        
        # Si tiene un tag comprobante (es un XML de autorización), parseamos el CDATA
        comprobante_tag = root.find('.//comprobante')
        if comprobante_tag is not None and comprobante_tag.text:
            factura_root = etree.fromstring(comprobante_tag.text.encode('utf-8'), parser=parser)
        else:
            factura_root = root

        # Extraer Info Tributaria
        info_tributaria = factura_root.find('infoTributaria')
        ruc = info_tributaria.find('ruc').text if info_tributaria is not None else ""
        razon_social = info_tributaria.find('razonSocial').text if info_tributaria is not None else ""
        
        # Extraer Info Factura
        info_factura = factura_root.find('infoFactura')
        fecha_emision = info_factura.find('fechaEmision').text if info_factura is not None else ""
        total = float(info_factura.find('importeTotal').text) if info_factura is not None else 0.0

        # Totales por impuesto
        base_0 = 0.0
        base_15 = 0.0
        monto_iva = 0.0

        total_con_impuestos = info_factura.find('totalConImpuestos') if info_factura is not None else None
        if total_con_impuestos is not None:
            for total_impuesto in total_con_impuestos.findall('totalImpuesto'):
                codigo = total_impuesto.find('codigo').text
                codigo_porcentaje = total_impuesto.find('codigoPorcentaje').text
                base = float(total_impuesto.find('baseImponible').text)
                valor = float(total_impuesto.find('valor').text)

                if codigo == "2": # IVA
                    if codigo_porcentaje == "0":
                        base_0 += base
                    elif codigo_porcentaje in ("2", "3", "4"): # 12%, 14%, 15% (historicos o actuales)
                        base_15 += base
                        monto_iva += valor

        return {
            "ruc_proveedor": ruc,
            "razon_social": razon_social,
            "fecha_emision": fecha_emision,
            "base_0": base_0,
            "base_15": base_15,
            "iva": monto_iva,
            "total": total
        }

    except Exception as e:
        raise ValueError(f"Error al parsear el XML: {str(e)}")

def generar_estructura_ats(compras: list, ventas: list) -> str:
    """
    Genera el XML del Anexo Transaccional Simplificado (ATS) en formato string.
    """
    root = etree.Element("iva")
    
    # Compras
    if compras:
        compras_el = etree.SubElement(root, "compras")
        for compra in compras:
            detalle_compras = etree.SubElement(compras_el, "detalleCompras")
            etree.SubElement(detalle_compras, "codSustento").text = compra.get("codSustento", "01")
            etree.SubElement(detalle_compras, "tpIdProv").text = compra.get("tpIdProv", "01")
            etree.SubElement(detalle_compras, "idProv").text = compra.get("idProv", "")
            etree.SubElement(detalle_compras, "tipoComprobante").text = compra.get("tipoComprobante", "01")
            etree.SubElement(detalle_compras, "fechaRegistro").text = compra.get("fechaRegistro", "")
            etree.SubElement(detalle_compras, "establecimiento").text = str(compra.get("establecimiento", "001")).zfill(3)
            etree.SubElement(detalle_compras, "puntoEmision").text = str(compra.get("puntoEmision", "001")).zfill(3)
            etree.SubElement(detalle_compras, "secuencial").text = str(compra.get("secuencial", "1")).zfill(9)
            etree.SubElement(detalle_compras, "fechaEmision").text = compra.get("fechaEmision", "")
            etree.SubElement(detalle_compras, "autorizacion").text = compra.get("autorizacion", "")
            etree.SubElement(detalle_compras, "baseNoObjetoIva").text = f"{compra.get('baseNoObjetoIva', 0.0):.2f}"
            etree.SubElement(detalle_compras, "baseImponible").text = f"{compra.get('baseImponible', 0.0):.2f}"
            etree.SubElement(detalle_compras, "baseImpGrav").text = f"{compra.get('baseImpGrav', 0.0):.2f}"
            etree.SubElement(detalle_compras, "montoIva").text = f"{compra.get('montoIva', 0.0):.2f}"

    # Ventas
    if ventas:
        ventas_el = etree.SubElement(root, "ventas")
        for venta in ventas:
            detalle_ventas = etree.SubElement(ventas_el, "detalleVentas")
            etree.SubElement(detalle_ventas, "tpIdCliente").text = venta.get("tpIdCliente", "04")
            etree.SubElement(detalle_ventas, "idCliente").text = venta.get("idCliente", "")
            etree.SubElement(detalle_ventas, "tipoComprobante").text = venta.get("tipoComprobante", "18")
            etree.SubElement(detalle_ventas, "numeroComprobantes").text = str(venta.get("numeroComprobantes", 1))
            etree.SubElement(detalle_ventas, "baseNoObjetoIva").text = f"{venta.get('baseNoObjetoIva', 0.0):.2f}"
            etree.SubElement(detalle_ventas, "baseImponible").text = f"{venta.get('baseImponible', 0.0):.2f}"
            etree.SubElement(detalle_ventas, "baseImpGrav").text = f"{venta.get('baseImpGrav', 0.0):.2f}"
            etree.SubElement(detalle_ventas, "montoIva").text = f"{venta.get('montoIva', 0.0):.2f}"

    xml_bytes = etree.tostring(root, xml_declaration=True, encoding="UTF-8", pretty_print=True)
    return xml_bytes.decode("UTF-8")
