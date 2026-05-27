import pytest
from datetime import datetime
from services.core import generate_access_key, validate_access_key

def test_generate_access_key():
    issue_date = datetime(2025, 5, 27)
    doc_type = "01"  # Factura
    ruc = "0999999999001"
    environment = "1"  # Pruebas
    establishment = "001"
    emission_point = "001"
    sequential = "000000001"
    
    key = generate_access_key(
        issue_date, doc_type, ruc, environment, establishment, emission_point, sequential
    )
    
    assert len(key) == 49
    assert validate_access_key(key) is True
