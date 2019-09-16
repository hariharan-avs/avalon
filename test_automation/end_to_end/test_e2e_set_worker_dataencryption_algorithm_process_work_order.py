import pytest
import logging
import json
import utility.file_utils as futils
import work_order_utility
import worker_utility
from workflow import process_request

logger = logging.getLogger(__name__)

def test_e2e_register_worker_update_dataencryption_algorithm_process_work_order(setup_config):
    """ Testing work order request with all valid parameter values. """

    # retrieve values from conftest session fixture
    worker_obj = setup_config[0]
    sig_obj = setup_config[1]
    uri_client = setup_config[2]
    private_key = setup_config[3]
    err_cd = setup_config[4]

    # # input and output names
    # input_json_file = r'./end_to_end/input/e2e_register_worker_update_dataencryption_algorithm_process_work_order_01.json'
    # output_json_file_name = 'e2e_register_worker_update_dataencryption_algorithm_process_work_order_01'
    # id_gen_01 = True
    # # expected response
    # check_worker_result_01 = {"error": {"code": 0}}
    # err_cd, worker_obj, input_json_str1, response = worker_utility.process_worker_actions(input_json_file, id_gen_01, output_json_file_name, worker_obj, uri_client, check_worker_result_01)
    #
    # if err_cd == 0:
    #     # input and output names
    #     input_json_file_02 = r'./end_to_end/input/e2e_register_worker_update_dataencryption_algorithm_process_work_order_02.json'
    #     output_json_file_name_02 = 'e2e_register_worker_update_dataencryption_algorithm_process_work_order_02'
    #     id_gen_02 = False
    #     # expected response
    #     check_worker_result_02 = {"result": {"workerId": ""}}
    #     err_cd, worker_obj, input_json_str1, response = worker_utility.process_worker_actions(input_json_file_02, id_gen_02, output_json_file_name_02, worker_obj, uri_client, check_worker_result_02)
    #     worker_obj.load_worker(response)
    if err_cd == 0:
        # input and output names
        input_json_file_03 = r'./end_to_end/input/e2e_register_worker_update_dataencryption_algorithm_process_work_order_03.json'
        output_json_file_name_03 = 'e2e_register_worker_update_dataencryption_algorithm_process_work_order_03'
        id_gen_03 = False
        # expected response
        check_worker_result_03 = {"error": {"code": 0}}
        err_cd, worker_obj, input_json_str1, response = worker_utility.process_worker_actions(input_json_file_03, id_gen_03, output_json_file_name_03, worker_obj, uri_client, check_worker_result_03)

    if err_cd == 0:
        # input and output names
        input_json_file_04 = r'./end_to_end/input/e2e_register_worker_update_dataencryption_algorithm_process_work_order_04.json'
        output_json_file_name_04 = 'e2e_register_worker_update_dataencryption_algorithm_process_work_order_04'
        input_type_04 = 'file'

        # expected response
        check_submit_04 = {"error": {"code": 5}}
        check_get_result_04 = {"error": {"code": 2}}
        tamper = {"params": {}}
        
        # # process worker actions
        # err_cd, input_json_str1_04, response_04, processing_time, worker_obj, sig_obj, encrypted_session_key = work_order_utility.process_work_order(input_json_file_04, input_type_04, output_json_file_name_04, worker_obj, sig_obj, uri_client, private_key, err_cd, check_submit_04, check_get_result_04)

        # process worker actions
        (err_cd, input_json_str1_04, response_04, processing_time,
        worker_obj, sig_obj, session_key, session_iv,
        enc_session_key) = work_order_utility.process_work_order(input_json_file_04,
        input_type_04, tamper, output_json_file_name_04, worker_obj, sig_obj,
        uri_client, private_key, err_cd, check_submit_04, check_get_result_04)

    assert err_cd == 0
