import pytest
import logging
import json
import work_order_utility

logger = logging.getLogger(__name__)

def test_work_order_worker_encryption_key(setup_config):
    """ Testing work order request with invalid workload parameter value. """

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    # input and output names
    input_json_file = r'./work_order/input/work_order_worker_encryption_key.json'
    input_type = 'file'
    output_json_file_name = 'work_order_worker_encryption_key'
    tamper = {"params": {}}

    # expected response
    check_submit = {"error": {"code": 5}}
    check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result = json.loads(check_result)

    # reset worker obj encryption key
    worker_obj.worker_encryption_key = "hsi"

    # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_file,
    input_type, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    assert err_cd == 0
