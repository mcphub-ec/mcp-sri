import base64
from io import BytesIO
from lxml import etree

try:
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import cm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
    from reportlab.graphics.barcode import code128
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

def generar_pdf_ride(xml_factura: str) -> str:
    """
    Genera el PDF del RIDE inyectando datos del XML de la factura SRI.
    Utiliza el motor Platypus de reportlab con cuadrículas estrictas.
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("ReportLab no está instalado.")

    # 1. Parseo Seguro del XML
    parser = etree.XMLParser(recover=True)
    root = etree.fromstring(xml_factura.encode('utf-8'), parser=parser)
    comprobante_tag = root.find('.//comprobante')
    if comprobante_tag is not None and comprobante_tag.text:
        factura_root = etree.fromstring(comprobante_tag.text.encode('utf-8'), parser=parser)
        fecha_autorizacion = root.findtext('.//fechaAutorizacion', 'NO AUTORIZADO')
        numero_autorizacion = root.findtext('.//numeroAutorizacion', '')
    else:
        factura_root = root
        fecha_autorizacion = 'NO AUTORIZADO'
        numero_autorizacion = ''

    def _t(parent, path, default=""):
        if parent is None: return default
        val = parent.findtext(path)
        return val.strip() if val else default

    info_tributaria = factura_root.find('infoTributaria')
    info_factura = factura_root.find('infoFactura')
    
    # Extracción de Datos
    razon_social = _t(info_tributaria, 'razonSocial')
    ruc = _t(info_tributaria, 'ruc')
    estab = _t(info_tributaria, 'estab', '000')
    pto = _t(info_tributaria, 'ptoEmi', '000')
    sec = _t(info_tributaria, 'secuencial', '000000000')
    num_factura = f"{estab}-{pto}-{sec}"
    clave_acceso = _t(info_tributaria, 'claveAcceso')
    if not numero_autorizacion: numero_autorizacion = clave_acceso
    
    ambiente = "PRODUCCIÓN" if _t(info_tributaria, 'ambiente') == "2" else "PRUEBAS"
    emision = "NORMAL" if _t(info_tributaria, 'tipoEmision') == "1" else "NORMAL"
    
    dir_matriz = _t(info_tributaria, 'dirMatriz')
    dir_sucursal = _t(info_factura, 'dirEstablecimiento', dir_matriz)
    obligado_cont = _t(info_factura, 'obligadoContabilidad', 'NO')
    contr_especial = _t(info_factura, 'contribuyenteEspecial')
    
    razon_comprador = _t(info_factura, 'razonSocialComprador')
    id_comprador = _t(info_factura, 'identificacionComprador')
    fecha_emision = _t(info_factura, 'fechaEmision')
    dir_comprador = _t(info_factura, 'direccionComprador', 'No proporcionada')

    # 2. Setup de Documento Platypus
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=cm, leftMargin=cm, topMargin=cm, bottomMargin=cm)
    story = []
    
    styles = getSampleStyleSheet()
    style_normal = styles["Normal"]
    style_normal.fontSize = 8
    
    style_bold = ParagraphStyle("Bold", parent=style_normal, fontName="Helvetica-Bold")
    style_center = ParagraphStyle("Center", parent=style_normal, alignment=TA_CENTER)
    style_right = ParagraphStyle("Right", parent=style_normal, alignment=TA_RIGHT)
    style_title = ParagraphStyle("Title", parent=style_bold, fontSize=12, alignment=TA_CENTER)

    # 3. CABECERA (50% / 50%)
    col_width = (letter[0] - 2*cm) / 2.0
    
    # Izquierda: Emisor
    left_content = []
    left_content.append(Spacer(1, 2*cm)) # Espacio para Logo
    left_content.append(Paragraph(razon_social, style_bold))
    left_content.append(Paragraph(f"<b>Dirección Matriz:</b> {dir_matriz}", style_normal))
    left_content.append(Paragraph(f"<b>Dirección Sucursal:</b> {dir_sucursal}", style_normal))
    if contr_especial:
        left_content.append(Paragraph(f"<b>Contribuyente Especial Nro:</b> {contr_especial}", style_normal))
    left_content.append(Paragraph(f"<b>OBLIGADO A LLEVAR CONTABILIDAD:</b> {obligado_cont}", style_normal))
    
    left_table = Table([[c] for c in left_content], colWidths=[col_width-0.5*cm])
    left_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOX', (0,1), (-1,-1), 0.5, colors.grey) # Box excluding logo
    ]))

    # Derecha: Tributaria
    right_content = []
    right_content.append(Paragraph(f"<b>R.U.C.:</b> {ruc}", style_bold))
    right_content.append(Paragraph("<b>F A C T U R A</b>", style_title))
    right_content.append(Paragraph(f"<b>No.</b> {num_factura}", style_normal))
    right_content.append(Paragraph("<b>NÚMERO DE AUTORIZACIÓN</b>", style_bold))
    right_content.append(Paragraph(numero_autorizacion, style_normal))
    right_content.append(Paragraph(f"<b>FECHA Y HORA DE AUTORIZACIÓN:</b> {fecha_autorizacion}", style_normal))
    right_content.append(Paragraph(f"<b>AMBIENTE:</b> {ambiente}", style_normal))
    right_content.append(Paragraph(f"<b>EMISIÓN:</b> {emision}", style_normal))
    right_content.append(Paragraph("<b>CLAVE DE ACCESO</b>", style_bold))
    
    if clave_acceso:
        barcode = code128.Code128(clave_acceso, barHeight=0.8*cm, barWidth=0.65)
        right_content.append(barcode)
        right_content.append(Paragraph(clave_acceso, style_center))

    right_table = Table([[c] for c in right_content], colWidths=[col_width-0.5*cm])
    right_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOX', (0,0), (-1,-1), 1, colors.black, None, (5,5,5,5)) # Rounded box effect
    ]))

    header_table = Table([[left_table, right_table]], colWidths=[col_width, col_width])
    header_table.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'TOP')]))
    story.append(header_table)
    story.append(Spacer(1, 0.5*cm))

    # 4. BLOQUE CLIENTE
    client_data = [
        [Paragraph(f"<b>Razón Social / Nombres y Apellidos:</b> {razon_comprador}", style_normal),
         Paragraph(f"<b>Identificación:</b> {id_comprador}", style_normal)],
        [Paragraph(f"<b>Fecha de Emisión:</b> {fecha_emision}", style_normal),
         Paragraph(f"<b>Dirección:</b> {dir_comprador}", style_normal)]
    ]
    client_table = Table(client_data, colWidths=[col_width*1.3, col_width*0.7])
    client_table.setStyle(TableStyle([
        ('BOX', (0,0), (-1,-1), 0.5, colors.black),
        ('VALIGN', (0,0), (-1,-1), 'TOP')
    ]))
    story.append(client_table)
    story.append(Spacer(1, 0.5*cm))

    # 5. DETALLES
    det_headers = ["Cod. Principal", "Cod. Auxiliar", "Cant", "Descripción", "Detalle Adic.", "Precio Unit.", "Descuento", "Precio Total"]
    det_data = [[Paragraph(f"<b>{h}</b>", style_center) for h in det_headers]]
    
    detalles_tags = factura_root.find('detalles')
    if detalles_tags is not None:
        for d in detalles_tags.findall('detalle'):
            cod_p = _t(d, 'codigoPrincipal')
            cod_a = _t(d, 'codigoAuxiliar', cod_p)
            cant = _t(d, 'cantidad')
            desc = _t(d, 'descripcion')
            p_unit = _t(d, 'precioUnitario')
            descuento = _t(d, 'descuento', '0.00')
            p_total = _t(d, 'precioTotalSinImpuesto')
            
            # Detalle adicional
            det_adic = ""
            det_ad_tags = d.find('detallesAdicionales')
            if det_ad_tags is not None:
                for da in det_ad_tags.findall('detAdicional'):
                    det_adic += f"{da.get('nombre')}: {da.get('valor')} "
            
            det_data.append([
                Paragraph(cod_p, style_normal),
                Paragraph(cod_a, style_normal),
                Paragraph(cant, style_right),
                Paragraph(desc, style_normal),
                Paragraph(det_adic, style_normal),
                Paragraph(p_unit, style_right),
                Paragraph(descuento, style_right),
                Paragraph(p_total, style_right)
            ])

    w_total = letter[0] - 2*cm
    col_w = [w_total*0.12, w_total*0.12, w_total*0.08, w_total*0.25, w_total*0.15, w_total*0.10, w_total*0.08, w_total*0.10]
    det_table = Table(det_data, colWidths=col_w, repeatRows=1)
    det_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
    ]))
    story.append(det_table)
    story.append(Spacer(1, 0.5*cm))

    # 6. PIE DE PÁGINA (65% / 35%)
    subtot_15 = 0.0
    subtot_0 = 0.0
    subtot_no_obj = 0.0
    subtot_exento = 0.0
    
    impuestos_tags = info_factura.find('totalConImpuestos')
    if impuestos_tags is not None:
        for imp in impuestos_tags.findall('totalImpuesto'):
            cod = _t(imp, 'codigo')
            cod_p = _t(imp, 'codigoPorcentaje')
            base = float(_t(imp, 'baseImponible', '0'))
            if cod == '2': # IVA
                if cod_p in ('2','3','4'): subtot_15 += base # 12, 14, 15
                elif cod_p == '0': subtot_0 += base
                elif cod_p == '6': subtot_no_obj += base
                elif cod_p == '7': subtot_exento += base

    subtot_sin = float(_t(info_factura, 'totalSinImpuestos', '0'))
    t_desc = float(_t(info_factura, 'totalDescuento', '0'))
    
    # IVA manual calculo para extraer solo la propina o totales del XML directamente si es posible
    iva_15 = 0.0
    if impuestos_tags is not None:
         for imp in impuestos_tags.findall('totalImpuesto'):
             if _t(imp, 'codigo') == '2' and _t(imp, 'codigoPorcentaje') in ('2','3','4'):
                 iva_15 += float(_t(imp, 'valor', '0'))
                 
    v_total = float(_t(info_factura, 'importeTotal', '0'))

    # Tabla Impuestos (Derecha 35%)
    w_imp = w_total * 0.35
    imp_data = [
        [Paragraph("SUBTOTAL 15%", style_normal), Paragraph(f"{subtot_15:.2f}", style_right)],
        [Paragraph("SUBTOTAL 0%", style_normal), Paragraph(f"{subtot_0:.2f}", style_right)],
        [Paragraph("SUBTOTAL NO OBJETO DE IVA", style_normal), Paragraph(f"{subtot_no_obj:.2f}", style_right)],
        [Paragraph("SUBTOTAL EXENTO DE IVA", style_normal), Paragraph(f"{subtot_exento:.2f}", style_right)],
        [Paragraph("SUBTOTAL SIN IMPUESTOS", style_normal), Paragraph(f"{subtot_sin:.2f}", style_right)],
        [Paragraph("TOTAL DESCUENTO", style_normal), Paragraph(f"{t_desc:.2f}", style_right)],
        [Paragraph("ICE", style_normal), Paragraph("0.00", style_right)],
        [Paragraph("IVA 15%", style_normal), Paragraph(f"{iva_15:.2f}", style_right)],
        [Paragraph("<b>VALOR TOTAL</b>", style_bold), Paragraph(f"<b>{v_total:.2f}</b>", style_right)]
    ]
    imp_table = Table(imp_data, colWidths=[w_imp*0.65, w_imp*0.35])
    imp_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
    ]))

    # Info Adicional y Forma Pago (Izquierda 65%)
    w_inf = w_total * 0.60
    inf_content = []
    info_adic_tags = factura_root.find('infoAdicional')
    if info_adic_tags is not None:
        for ca in info_adic_tags.findall('campoAdicional'):
            nom = ca.get('nombre', '')
            val = ca.text or ''
            inf_content.append(Paragraph(f"<b>{nom}:</b> {val}", style_normal))
    
    if not inf_content:
        inf_content.append(Paragraph("Ninguna", style_normal))
        
    inf_table = Table([[c] for c in inf_content], colWidths=[w_inf])
    inf_table.setStyle(TableStyle([
        ('BOX', (0,0), (-1,-1), 0.5, colors.black)
    ]))
    
    pagos_tags = info_factura.find('pagos')
    pago_data = [[Paragraph("<b>Forma de Pago</b>", style_center), Paragraph("<b>Valor</b>", style_center)]]
    if pagos_tags is not None:
        for p in pagos_tags.findall('pago'):
            fp = _t(p, 'formaPago')
            tot = _t(p, 'total')
            pago_data.append([Paragraph(fp, style_normal), Paragraph(tot, style_right)])
            
    pago_table = Table(pago_data, colWidths=[w_inf*0.7, w_inf*0.3])
    pago_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
    ]))

    left_footer = Table([
        [Paragraph("<b>Información Adicional</b>", style_bold)],
        [inf_table],
        [Spacer(1, 0.3*cm)],
        [pago_table]
    ], colWidths=[w_inf])

    footer_table = Table([[left_footer, imp_table]], colWidths=[w_total*0.65, w_total*0.35])
    footer_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP')
    ]))
    
    story.append(footer_table)

    doc.build(story)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()

    return base64.b64encode(pdf_bytes).decode('utf-8')

