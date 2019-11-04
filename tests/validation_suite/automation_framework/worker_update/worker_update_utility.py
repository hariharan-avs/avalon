import pytest
import time
import logging
import json

import automation_framework.worker.worker_params as worker
from automation_framework.worker_update.worker_update_params import WorkerUpdate
from automation_framework.utilities.workflow import process_request
from automation_framework.utilities.workflow import validate_response_code

logger = logging.getLogger(__name__)

def process_worker_update(input_request, input_type, tamper,
               output_json_file_name, uri_client, worker_obj, sig_obj,
               request_id, check_update_result) :
    ''' Function to process worker actions.
        Reads input json file of the test case.
        Triggers create worker request, process request and validate response.
        Input Parameters : input_json_file, id_gen, output_json_file_name,
        worker_obj, uri_client, check_worker_result
        Returns : err_cd, worker_obj, input_json_str1, response. '''

    logger.info("----- Testing Worker Update -----")

    if input_type == "object" :
        # process work order get result and retrieve response
        logger.info("----- Constructing WorkerUpdate from input object -----")
        input_update = json.loads(input_request.to_string())
    else :
        logger.info("----- Constructing WorkerUpdate from input json -----")
        worker_update_obj = WorkerUpdate()
        worker_update_obj.add_json_values(input_request, worker_obj, sig_obj)
        input_update = json.loads(worker_update_obj.to_string())

    # submit work order request and retrieve response
    response = process_request(uri_client, input_update,
                              output_json_file_name)
    # validate work order response and get error code
    err_cd = validate_response_code(response, check_update_result)

    response_tup = (err_cd, input_update, response)
    return response_tup
