import pytest
import time
import logging

from automation_framework.utilities.workflow import process_request
from automation_framework.utilities.workflow import validate_response_code

logger = logging.getLogger(__name__)

def process_worker_actions(input_json_str, tamper, output_json_file_name,
               uri_client, worker_obj, sig_obj, check_worker_result) :
    ''' Function to process worker actions.
        Reads input json file of the test case.
        Triggers create worker request, process request and validate response.
        Input Parameters : input_json_file, id_gen, output_json_file_name,
        worker_obj, uri_client, check_worker_result
        Returns : err_cd, worker_obj, input_json_str1, response. '''

    logger.info("----- Testing Worker Actions -----")

    if input_json_str == {} :
        # process work order get result and retrieve response
        logger.info("----- Constructing WorkOrderGetResult -----")
        worker_upd_obj = WorkOrderGetResult()

        input_get_result = json.loads(get_result_obj.to_string())
    else :
        input_get_result = input_json_str

    # submit work order request and retrieve response
    response = process_request(uri_client, input_json_str1,
                              output_json_file_name)
    # validate work order response and get error code
    err_cd = validate_response_code(response, check_worker_result)

    return err_cd, worker_obj, input_json_str1, response
