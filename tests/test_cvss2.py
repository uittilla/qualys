cvss2_vector = 'AV:N/AC:L/Au:S/C:P/I:P/A:N/E:POC/RL:OF/RC:C'

def test_cvss2_vector(mock_Qualys_Cvss2):
    assert mock_Qualys_Cvss2().convert_cvss2(cvss2_vector) != cvss2_vector