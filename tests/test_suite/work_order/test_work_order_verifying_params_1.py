import pytest
import logging
import json
import work_order_utility
import time
import utility.file_utils as futils

logger = logging.getLogger(__name__)

def test_work_order_submit_twice_params(setup_config):
    """ Testing work order request by passing the parameters twice in the request."""

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    #Passing input and output file names
    input_json_file = './work_order/input/work_order_submit_twice_params.json'
    input_type = 'file'
    output_json_file_name = 'work_order_submit_twice_params'
    tamper = {"params": {}}

    #Checking expected responses for work order submit and work order get result
    check_submit = {"error": {"code": 5}}
    check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result = json.loads(check_result)

    # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_file,
    input_type, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    assert err_cd == 0

def test_work_order_submit_datahash_calculation(setup_config):
    """ Testing work order request by passing required parameters for dataHash calculation."""

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    #Passing input and output file names
    input_json_file = './work_order/input/work_order_submit_datahash_calculation.json'
    input_type = 'file'
    output_json_file_name = 'work_order_submit_datahash_calculation'
    tamper = {"params": {}}

    #Checking expected responses for work order submit and work order get result
    check_submit = {"error": {"code": 5}}
    check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result = json.loads(check_result)

    # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_file,
    input_type, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    assert err_cd == 0

def test_work_order_multiple_data_ecoresult(setup_config):
    """ Testing work order request with multiple data in indata using eco-result has workloadid  """

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    # input and output names
    input_json_file = './work_order/input/work_order_multiple_data_echoresult.json'
    input_type = 'file'
    output_json_file_name = 'work_order_multiple_data_echoresult'
    tamper = {"params": {}}

    # expected response
    check_submit = {"error": {"code": 5}}
    check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result = json.loads(check_result)

    # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_file,
    input_type, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    if err_cd == 0:
        err_cd = work_order_utility.verify_work_order_signature(response,
                 sig_obj, worker_obj)

    if err_cd == 0:
        (err_cd, decrypted_data) = (work_order_utility.
        decrypt_work_order_response(response, session_key, session_iv))

    if err_cd == 0:
        logger.info('''Test Case Success : Work Order Processed successfully
                   with Signature Verification and Decrypted Response for multiple data of indata \n''')
    else:
        logger.info('''Test Case Failed : Work Order Not Processed successfully
                   with Signature Verification and Decrypted Response''')

    assert err_cd == 0

def test_work_order_specialcharacter_data_single_index_indata(setup_config):
    """ Testing work order request with all special characters in index of indata """

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    # input and output names
    input_json_file = './work_order/input/work_order_specialcharacter_data_single_index_indata.json'
    input_type = 'file'
    output_json_file_name = 'work_order_specialcharacter_data_single_index_indata'
    tamper = {"params": {}}

    # expected response
    check_submit = {"error": {"code": 5}}
    check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result = json.loads(check_result)

    # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_file,
    input_type, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    if err_cd == 0:
        err_cd = work_order_utility.verify_work_order_signature(response,
                 sig_obj, worker_obj)

    if err_cd == 0:
        (err_cd, decrypted_data) = (work_order_utility.
        decrypt_work_order_response(response, session_key, session_iv))

    if err_cd == 0:
        logger.info('''Test Case Success : Work Order Processed successfully
                   with Signature Verification and Decrypted Response for all special characters in indata \n''')
    else:
        logger.info('''Test Case Failed : Work Order Not Processed successfully
                   with Signature Verification and Decrypted Response''')

    assert err_cd == 0

def test_wo_req_twice_same_wo_id(setup_config):
    """ Test work order submit by passing request twice with same work order id."""

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    #Passing input and output file names
    input_json_file = './work_order/input/work_order_req_twice_same_wo_id.json'
    input_type = 'file'
    output_json_file_name = 'wo_req_twice_same_wo_id'
    tamper = {"params": {"before_sign": {"workOrderId": ""}}}

    # expected response
    check_submit = {"error": {"code": 5}}
    check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result = json.loads(check_result)

    # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_file,
    input_type, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    time.sleep(30)

    if err_cd == 0:

    	#Passing input and output file names
        input_json_file = './work_order/input/work_order_req_twice_same_wo_id.json'
        input_type = 'file'
        output_json_file_name = 'wo_req_twice_same_wo_id'
        tamper = {"params": {"before_sign": {"workOrderId": ""}}}

        # expected response
        check_submit = {"error": {"code": 5}}
        check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                           "workerId": "", "requesterId": "", "workerNonce": "",
                           "workerSignature": "", "outData": ""}}'''
        check_get_result = json.loads(check_result)

        # process worker actions
        (err_cd, input_json_str1, response, processing_time,
        worker_obj, sig_obj, session_key, session_iv,
        enc_session_key) = work_order_utility.process_work_order(input_json_file,
        input_type, tamper, output_json_file_name, worker_obj, sig_obj,
        uri_client, private_key, err_cd, check_submit, check_get_result)

    assert err_cd == 0

def test_wo_req_twice_diff_wo_id(setup_config):
    """ Test work order submit by passing request twice with different work order id."""

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    #Passing input and output file names
    input_json_file = './work_order/input/work_order_req_twice_first_wo_id.json'
    input_type = 'file'
    output_json_file_name = 'wo_req_twice_same_wo_id'
    tamper = {"params": {}}

    # expected response
    check_submit = {"error": {"code": 5}}
    check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result = json.loads(check_result)

    # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_file,
    input_type, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    if err_cd == 0:

    	#Passing input and output file names
        input_json_file = './work_order/input/work_order_req_twice_diff_wo_id.json'
        input_type = 'file'
        output_json_file_name = 'test_wo_req_twice_diff_wo_id'
        tamper = {"params": {}}

        # expected response
        check_submit = {"error": {"code": 5}}
        check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                           "workerId": "", "requesterId": "", "workerNonce": "",
                           "workerSignature": "", "outData": ""}}'''
        check_get_result = json.loads(check_result)

        # process worker actions
        (err_cd, input_json_str1, response, processing_time,
        worker_obj, sig_obj, session_key, session_iv,
        enc_session_key) = work_order_utility.process_work_order(input_json_file,
        input_type, tamper, output_json_file_name, worker_obj, sig_obj,
        uri_client, private_key, err_cd, check_submit, check_get_result)

    assert err_cd == 0

def test_wo_req_twice_same_wo_id_diff_worker_id(setup_config):
    """ Test work order submit by passing request twice with same work order id but different worker id."""

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    #Passing input and output file names
    input_json_file = './work_order/input/work_order_req_twice_second_wo_id.json'
    input_type = 'file'
    output_json_file_name = 'work_order_req_twice_same_wo_id'
    tamper = {"params": {}}

    # expected response
    check_submit = {"error": {"code": 5}}
    check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result = json.loads(check_result)

    # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_file,
    input_type, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    #assert err_cd == 0
    # get work order id and request id
    work_order_id_01 = response["result"]["workOrderId"]

    time.sleep(30)
	#Passing input and output file names
    input_json_file_02 = './work_order/input/work_order_req_twice_same_wo_id_diff_worker_id.json'
    input_type_02 = 'string'
    output_json_file_name = 'work_order_req_twice_same_wo_id_diff_worker_id'
    tamper = {"params": {}}

    logger.info("------------------Input file name: %s ---------------\n", input_json_file_02)
    input_json_str1 = futils.read_json_file(input_json_file_02)
    # reuse workorder id and incrment reuest id
    input_json_temp = json.loads(input_json_str1)
    input_json_temp["params"]["workOrderId"] = work_order_id_01
    input_json_str2 = json.dumps(input_json_temp)

    # expected response
    check_submit = {"error": {"code": 5}}
    check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result = json.loads(check_result)

    # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_str2,
    input_type_02, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    assert err_cd == 0


def test_work_order_diff_text_data_indata_echoClient(setup_config):
    """ Testing work order request with multiple data in indata using eco-result has workloadid  """

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    # input and output names
    input_json_file = './work_order/input/work_order_diff_text_data_indata_echoClient.json'
    input_type = 'file'
    output_json_file_name = 'work_order_diff_text_data_indata_echoClient'
    tamper = {"params": {}}

    # expected response
    check_submit = {"error": {"code": 5}}
    check_result = '''{"result": {"workOrderId": "", "workloadId": "",
                       "workerId": "", "requesterId": "", "workerNonce": "",
                       "workerSignature": "", "outData": ""}}'''
    check_get_result = json.loads(check_result)

    # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_file,
    input_type, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    if err_cd == 0:
        err_cd = work_order_utility.verify_work_order_signature(response,
                 sig_obj, worker_obj)

    if err_cd == 0:
        (err_cd, decrypted_data) = (work_order_utility.
        decrypt_work_order_response(response, session_key, session_iv))

    if err_cd == 0:
        logger.info('''Test Case Success : Work Order Processed successfully
                   with Signature Verification and Decrypted Response for passing the parameters twice in the request
                   \n''')
    else:
        logger.info('''Test Case Failed : Work Order Not Processed successfully
                   with Signature Verification and Decrypted Response ''')
    assert err_cd == 0
