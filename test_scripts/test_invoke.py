import pytest
from pytest_jsonreport.plugin import JSONReport

plugin = JSONReport()
pytest.main(['test_step_2.py'], plugins=[plugin])

plugin.save_report('report.json')
