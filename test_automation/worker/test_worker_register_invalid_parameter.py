import pytest
import logging
import json
import worker_utility

logger = logging.getLogger(__name__)

def test_worker_register_invalid_parameter(setup_config):

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    # input and output names
    input_json_file = r'./worker/input/worker_register_invalid_parameter.json'
    id_gen = False
    output_json_file_name = 'worker_register_invalid_parameter'

    # expected response
    check_worker_result = {"error": {"code": 2}}

    err_cd, worker_obj, input_json_str1, response = worker_utility.process_worker_actions(input_json_file, id_gen, output_json_file_name, worker_obj, uri_client, check_worker_result)

    assert err_cd == 0
