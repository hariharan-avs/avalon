import pytest
import logging
import json
import utility.file_utils as futils
import work_order_utility
import time

logger = logging.getLogger(__name__)

def test_work_order_with_existing_workOrderId(setup_config):
    """ Testing work order request with all valid parameter values. """

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    # input and output names
    input_json_01 = r'./work_order/input/work_order_with_existing_workOrderId.json'
    input_type_01 = 'file'
    output_json_file_name_01 = 'work_order_with_existing_workOrderId_01'
    tamper = {"params": {}}

    # expected response
    check_submit_01 = {"error": {"code": 5}}
    check_result_01 = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result_01 = json.loads(check_result_01)

    # process worker actions
    (err_cd, input_json_str1, response_01, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_01,
    input_type_01, tamper, output_json_file_name_01, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit_01, check_get_result_01)

    # get work order id and request id
    work_order_id_01 = response_01["result"]["workOrderId"]
    request_id_02 = response_01["id"] + 1

    logger.info("------------------Input file name: %s ---------------\n", input_json_01)
    input_json_str1 = futils.read_json_file(input_json_01)
    # reuse workorder id and incrment reuest id
    input_json_temp = json.loads(input_json_str1)
    input_json_temp["params"]["workOrderId"] = work_order_id_01
    input_json_temp["id"] = request_id_02
    input_json_str2 = json.dumps(input_json_temp)

    # input and output names
    input_json_02 = input_json_str2
    input_type_02 = 'string'
    output_json_file_name_02 = 'work_order_with_existing_workOrderId_02'
    # expected response
    check_submit_02 = {"error": {"code": 5}}
    check_result_02 = '''{"result": {"workOrderId": "", "workloadId": "",
                      "workerId": "", "requesterId": "", "workerNonce": "",
                      "workerSignature": "", "outData": ""}}'''
    check_get_result_02 = json.loads(check_result_02)

    time.sleep(30)
    # process worker actions
    (err_cd, input_json_str2, response_02, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_02,
    input_type_02, tamper, output_json_file_name_02, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit_02, check_get_result_02)

    assert err_cd == 0
