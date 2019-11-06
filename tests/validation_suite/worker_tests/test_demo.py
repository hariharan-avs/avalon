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
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    # input and output names
    input_json_file = './worker_tests/input/worker_update.json'
    input_type = 'file'
    output_json_file_name = 'worker_update'
    tamper = {"params": {}}
    request_method = "WorkerUpdate"
    request_id = 0

    # expected response
    check_update_result = {"error": {"code": 0}}

    # process worker update
    request_tup = (input_json_file, input_type, tamper, output_json_file_name,
                   uri_client, request_method, worker_obj, sig_obj,
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
