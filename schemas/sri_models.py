from typing import TypedDict, List, Optional
from enum import Enum

class TipoContribuyente(str, Enum):
    PERSONA_NATURAL = "PERSONA_NATURAL"
    SOCIEDAD = "SOCIEDAD"
    CONTRIBUYENTE_ESPECIAL = "CONTRIBUYENTE_ESPECIAL"
    ENTIDAD_PUBLICA = "ENTIDAD_PUBLICA"

class RetencionRequest(TypedDict):
    tipo_contribuyente_emisor: TipoContribuyente
    tipo_contribuyente_receptor: TipoContribuyente
    codigo_concepto: str
    monto_base: float

class RetencionResponse(TypedDict):
    porcentaje_retencion: float
    valor_retenido: float
    monto_base: float
    codigo_concepto: str
    descripcion_concepto: str

class RolPagosRequest(TypedDict):
    sueldo_base: float
    dias_trabajados: int
    horas_extras: Optional[float]

class RolPagosResponse(TypedDict):
    ingresos: dict
    deducciones: dict
    provisiones_patronales: dict
    liquido_a_recibir: float

class AtsCompra(TypedDict):
    codSustento: str
    tpIdProv: str
    idProv: str
    tipoComprobante: str
    fechaRegistro: str
    establecimiento: str
    puntoEmision: str
    secuencial: str
    fechaEmision: str
    autorizacion: str
    baseNoObjetoIva: float
    baseImponible: float
    baseImpGrav: float
    montoIva: float

class AtsVenta(TypedDict):
    tpIdCliente: str
    idCliente: str
    tipoComprobante: str
    numeroComprobantes: int
    baseNoObjetoIva: float
    baseImponible: float
    baseImpGrav: float
    montoIva: float

class AtsRequest(TypedDict):
    compras: List[AtsCompra]
    ventas: List[AtsVenta]
