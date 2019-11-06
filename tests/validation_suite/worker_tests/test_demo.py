import pytest
import logging
import json

import automation_framework.worker.worker_params as worker
from automation_framework.utilities.validate_request import validate_request
import automation_framework.work_order_submit.work_order_submit_utility as wo_utility
import automation_framework.work_order_get_result.work_order_get_result_utility as wo_get_result

logger = logging.getLogger(__name__)

def test_worker_update(setup_config):
    """ Testing worker update request with all valid parameter values. """

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    uri_client = setup_config[1]
    private_key = setup_config[2]
    err_cd = setup_config[3]

    # input and output names
    input_json_file = './worker_tests/input/worker_update.json'
    input_type = 'file'
    output_json_file_name = 'worker_update'
    tamper = {"params": {}}
    request_method = ""
    request_id = 0

    # expected response
    check_update_result = {"error": {"code": 0}}

    # process worker update
    request_tup = (input_json_file, input_type, tamper, output_json_file_name,
                   uri_client, request_method, worker_obj,
                   request_id, check_update_result)

    response_tup = validate_request(request_tup)

    err_cd = response_tup[0]
    input_update = response_tup[1]
    response = response_tup[2]

    if err_cd == 0:
        logger.info('''Test Case Success : Worker Update request
                    Processed successfully \n''')
    else:
        logger.info('''Test Case Failure : Worker Update request
                    failed to process successfully \n''')

    assert err_cd == 0

def test_worker_update_invalid_parameter(setup_config):
    """ Testing worker update request with all valid parameter values. """

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    uri_client = setup_config[1]
    private_key = setup_config[2]
    err_cd = setup_config[3]

    # input and output names
    input_json_file = './worker_tests/input/worker_update_invalid_parameter.json'
    input_type = 'file'
    output_json_file_name = 'worker_update_invalid_parameter'
    tamper = {"params": {}}
    request_method = ""
    request_id = 0

    # expected response
    check_update_result = {"error": {"code": 2}}

    # process worker update
    request_tup = (input_json_file, input_type, tamper, output_json_file_name,
                   uri_client, request_method, worker_obj,
                   request_id, check_update_result)

    response_tup = validate_request(request_tup)

    err_cd = response_tup[0]
    input_update = response_tup[1]
    response = response_tup[2]

    if err_cd == 0:
        logger.info('''Test Case Success : Worker Update request
                    Processed successfully \n''')
    else:
        logger.info('''Test Case Failure : Worker Update request
                    failed to process successfully \n''')

    assert err_cd == 0

def test_worker_update_unknown_parameter(setup_config):
    """ Testing worker update request with all valid parameter values. """

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    uri_client = setup_config[1]
    private_key = setup_config[2]
    err_cd = setup_config[3]

    # input and output names
    # input_json_file = './worker_tests/input/worker_update_unknown_parameter.json'
    input_json_file = './worker_tests/input/worker_update.json'
    input_type = 'file'
    output_json_file_name = 'worker_update_unknown_parameter'
    tamper = {"params": {"details": {"name": "TEST"}}}
    request_method = ""
    request_id = 0

    # expected response
    check_update_result = {"error": {"code": 2}}

    # process worker update
    request_tup = (input_json_file, input_type, tamper, output_json_file_name,
                   uri_client, request_method, worker_obj,
                   request_id, check_update_result)

    response_tup = validate_request(request_tup)

    err_cd = response_tup[0]
    input_update = response_tup[1]
    response = response_tup[2]

    if err_cd == 0:
        logger.info('''Test Case Success : Worker Update request
                    Processed successfully \n''')
    else:
        logger.info('''Test Case Failure : Worker Update request
                    failed to process successfully \n''')

    assert err_cd == 0
