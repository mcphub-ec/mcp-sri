from schemas.sri_models import TipoContribuyente

# Tabla de porcentajes de retención en la fuente (simplificada para propósitos de la herramienta)
# Estructura: código -> {"porcentaje": float, "descripcion": str}
CONCEPTOS_RETENCION_RENTA = {
    "303": {"porcentaje": 10.0, "descripcion": "Honorarios profesionales"},
    "304": {"porcentaje": 8.0, "descripcion": "Notarios y registradores"},
    "309": {"porcentaje": 2.0, "descripcion": "Servicios predominantemente intelectuales"},
    "310": {"porcentaje": 1.75, "descripcion": "Transporte privado de carga"},
    "312": {"porcentaje": 1.75, "descripcion": "Transferencia de bienes muebles de naturaleza corporal"},
    "312A": {"porcentaje": 2.75, "descripcion": "Servicios predominantemente manuales"},
    "320": {"porcentaje": 1.0, "descripcion": "Adquisición de bienes agrícolas, avícolas, pecuarios"},
    "332": {"porcentaje": 0.0, "descripcion": "Compras locales de bienes que se comercialicen sin transformación"},
    "343": {"porcentaje": 1.0, "descripcion": "Energía eléctrica"},
}

def calcular_retencion_renta(
    emisor: TipoContribuyente,
    receptor: TipoContribuyente,
    codigo_concepto: str,
    monto_base: float
) -> dict:
    """
    Calcula la retención en la fuente (renta) en base a un código de concepto.
    El emisor es quien emite la factura (el proveedor).
    El receptor es quien recibe la factura y realiza el pago (agente de retención).
    """
    if receptor == TipoContribuyente.PERSONA_NATURAL:
        # Por lo general, personas naturales no obligadas a llevar contabilidad no retienen
        # a menos que tengan una designación específica. Para este cálculo básico:
        return {"porcentaje_retencion": 0.0, "valor_retenido": 0.0, "monto_base": monto_base, "codigo_concepto": codigo_concepto, "descripcion_concepto": "No agente de retención"}

    concepto = CONCEPTOS_RETENCION_RENTA.get(codigo_concepto)
    if not concepto:
        raise ValueError(f"Código de retención {codigo_concepto} no encontrado o no soportado.")
    
    porcentaje = concepto["porcentaje"]
    valor = round(monto_base * (porcentaje / 100), 2)

    return {
        "porcentaje_retencion": porcentaje,
        "valor_retenido": valor,
        "monto_base": monto_base,
        "codigo_concepto": codigo_concepto,
        "descripcion_concepto": concepto["descripcion"]
    }

def calcular_rol_pagos(sueldo_base: float, dias_trabajados: int = 30, horas_extras: float = 0.0) -> dict:
    """
    Calcula de manera determinista un rol de pagos.
    Incluye IESS personal, patronal y provisiones (D13, D14, Fondos de Reserva).
    """
    SBU = 460.0  # Salario Básico Unificado 2024
    
    # Proporcional de sueldo por días trabajados
    sueldo_ganado = round((sueldo_base / 30) * dias_trabajados, 2)
    total_ingresos = round(sueldo_ganado + horas_extras, 2)
    
    # IESS
    aporte_personal = round(total_ingresos * 0.0945, 2)
    aporte_patronal = round(total_ingresos * 0.1115, 2)
    
    # Provisiones
    # Décimo Tercero: doceava parte de todos los ingresos del mes
    decimo_tercero = round(total_ingresos / 12, 2)
    
    # Décimo Cuarto: SBU proporcional a los días
    decimo_cuarto_mensual = round(SBU / 12, 2)
    decimo_cuarto = round((decimo_cuarto_mensual / 30) * dias_trabajados, 2)
    
    # Fondos de reserva: se pagan después del año (8.33% del ingreso).
    # Asumimos que se provisionan
    fondos_reserva = round(total_ingresos * 0.0833, 2)

    liquido = round(total_ingresos - aporte_personal, 2)

    return {
        "ingresos": {
            "sueldo_ganado": sueldo_ganado,
            "horas_extras": horas_extras,
            "total_ingresos": total_ingresos
        },
        "deducciones": {
            "aporte_personal_iess": aporte_personal,
            "total_deducciones": aporte_personal
        },
        "provisiones_patronales": {
            "aporte_patronal_iess": aporte_patronal,
            "decimo_tercero": decimo_tercero,
            "decimo_cuarto": decimo_cuarto,
            "fondos_reserva": fondos_reserva,
            "total_provisiones": round(aporte_patronal + decimo_tercero + decimo_cuarto + fondos_reserva, 2)
        },
        "liquido_a_recibir": liquido
    }
