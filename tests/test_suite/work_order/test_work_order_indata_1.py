import pytest
import logging
import json
import work_order_utility

logger = logging.getLogger(__name__)

def test_work_order_data_datahash_null(setup_config):
    """ Testing work order request by passing data and datahash null in all index. """

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    # input and output names
    input_json_file = './work_order/input/work_order_data_datahash_null.json'
    input_type = 'file'
    output_json_file_name = 'work_order_data_datahash_null'
    tamper = {"params": {}}

    # expected response
    check_submit = {"error": {"code": 5}}
    check_get_result = {"error": {"code": 2}}

   # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_file,
    input_type, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    if err_cd == 0:
        logger.info('''Test Case Success : WorkOrderGetResult response
        has received expected result for passing a null  in data and dataHash and the message. \n''')
    else:
        logger.info('''Test Case Failed : WorkOrderGetResult response
        did not contain expected result. ''')

    assert err_cd == 0

def test_work_order_datahash_random_str(setup_config):
    """
    Testing work order request by passing random string in datahash.
    """
    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    # Passing input and output file names
    input_json_file = './work_order/input/work_order_datahash_random_str.json'
    input_type = 'file'
    output_json_file_name = 'work_order_datahash_random_str'
    tamper = {"params": {}}

    # Checking expected responses for the work order submit and work order get result
    check_submit = {"error": {"code": 5}}
    check_get_result = {"error": {"code": 2}}

    # process worker actions
    (err_cd, input_json_str1, response, processing_time,
    worker_obj, sig_obj, session_key, session_iv,
    enc_session_key) = work_order_utility.process_work_order(input_json_file,
    input_type, tamper, output_json_file_name, worker_obj, sig_obj,
    uri_client, private_key, err_cd, check_submit, check_get_result)

    if err_cd == 0:
        logger.info('''Test Case Success : WorkOrderGetResult response
        has received expected result for passing a random string in dataHash and the message. \n''')
    else:
        logger.info('''Test Case Failed : WorkOrderGetResult response
        did not contain expected result. ''')

    assert err_cd == 0
