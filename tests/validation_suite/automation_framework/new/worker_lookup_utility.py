import pytest
import time
import logging

from automation_framework.utilities.workflow import process_request
from automation_framework.utilities.workflow import validate_response_code

logger = logging.getLogger(__name__)

def process_worker_lookup(input_json_str, tamper, output_json_file_name,
               uri_client, worker_obj, sig_obj, worker_type, request_id,
               check_lookup_result) :
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
        worker_lookup_obj = WorkerLookUp()
        worker_lookup_obj.set_worker_type(worker_type)
        worker_lookup_obj.set_request_id(request_id)
        input_lookup = json.loads(get_result_obj.to_string())
    else :
        worker_lookup_obj = WorkerLookUp()
        worker_lookup_obj.add_json_values(input_json_str)
        input_lookup = json.loads(get_result_obj.to_string())

    # submit work order request and retrieve response
    response = process_request(uri_client, input_lookup,
                              output_json_file_name)
    # validate work order response and get error code
    err_cd = validate_response_code(response, check_lookup_result)

    response_tup = (err_cd, worker_obj, input_json_str1, response)
    return response_tup
