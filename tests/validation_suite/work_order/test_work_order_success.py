import pytest
import logging
import json
from automation_framework.utilities.validate_request import validate_request

logger = logging.getLogger(__name__)

def test_work_order_success(setup_config):
    """ Testing work order request with all valid parameter values. """

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    # input and output names
    input_json_file = './work_order/input/work_order_success.json'
    input_type = 'file'
    output_json_file_name = 'work_order_success'
    tamper = {"params": {}}

    # expected response
    check_submit = {"error": {"code": 5}}
    check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result = json.loads(check_result)

    # process worker actions
    request_tup=(input_json_file, input_type, tamper, output_json_file_name,
                worker_obj, sig_obj, uri_client, private_key, err_cd,
                check_submit, check_get_result)
    response_tup = validate_request(request_tup)

    err_cd = response_tup[0]
    input_json_str1 = response_tup[1]
    response = response_tup[2]
    processing_time = response_tup[3]
    session_key = response_tup[4]
    session_iv = response_tup[5]
    encrypted_session_key = response_tup[6]

    # if err_cd == 0:
    #     err_cd = work_order_utility.verify_work_order_signature(response,
    #              sig_obj, worker_obj)
    #
    # if err_cd == 0:
    #     (err_cd, decrypted_data) = (work_order_utility.
    #     decrypt_work_order_response(response, session_key, session_iv))
    #
    # if err_cd == 0:
    #     logger.info('''Test Case Success : Work Order Processed successfully
    #                with Signature Verification and Decrypted Response \n''')
    # else:
    #     logger.info('''Test Case Failed : Work Order Not Processed successfully
    #                with Signature Verification and Decrypted Response''')

    assert err_cd == 0
