app_banner = 'Qualys Vulnerability Tracking'
data_path  = '/Users/mark.ibbotson/Dev/sec/qualys/data/'

def test_app_banner(mock_QualysConfig):
    assert mock_QualysConfig().get_app_banner() == app_banner

def test_data_path(mock_QualysConfig):
    assert mock_QualysConfig().get_data_path()  == data_path