import pytest
import json
import os
import sys
import logging
import automation_framework.utilities.file_utils as futils
import automation_framework.work_order_submit.work_order_submit_utility as wo_utility
import automation_framework.work_order_get_result.work_order_get_result_utility as wo_get_result
import automation_framework.worker_update.worker_update_utility as worker_update
import automation_framework.worker.worker_utility as worker_utility
import automation_framework.worker.worker_params as worker
#import automation_framework.worker.worker_utility as worker_utility
from automation_framework.utilities.workflow import process_request
from automation_framework.utilities.workflow import validate_response_code

logger = logging.getLogger(__name__)

def validate_request(request_tup) :

    input_temp = request_tup[0]
    input_type = request_tup[1]
    tamper = request_tup[2]
    output_json_file_name = request_tup[3]
    uri_client = request_tup[4]
    request_method = request_tup[5]

    try :
        if input_type == "file" :
            # read json input file for the test case
            logger.info("------ Input file name: %s ------\n", input_temp)
            input_json = futils.read_json_file(input_temp)
            logger.info("------ Loaded file data: %s ------\n", input_temp)
        elif input_type == "string" :
            input_json = input_temp
            logger.info("------ Loaded string data: %s ------\n", input_request)

        input_request = json.loads(input_json)
        logger.info("Json loaded : %s \n", input_request)
    except :
        logger.info('''Invalid Json Input.
                Submitting to enclave without modifications to test response''')

        response = process_request(uri_client, input_temp,
                   output_json_file_name)
        err_cd = validate_response_code(response, check_result_1)

    if input_type == "object" :
        input_method = request_method
        input_request = input_temp
    else :
        input_method = input_request["method"]

        logger.info("Json input_method : %s \n", input_method)
        logger.info("Json Str 2 loaded : %s \n", input_request)

    if input_method == "WorkOrderSubmit" :
        worker_obj = request_tup[6]
        # sig_obj = request_tup[7]
        # private_key = request_tup[8]
        # err_cd = request_tup[9]
        # check_result_1 = request_tup[10]
        private_key = request_tup[7]
        err_cd = request_tup[8]
        check_result_1 = request_tup[9]

        # response_tup = wo_utility.process_work_order(input_request, input_type,
        #                tamper, output_json_file_name, uri_client, worker_obj,
        #                sig_obj, input_method, private_key, err_cd,
        #                check_result_1)

        response_tup = wo_utility.process_work_order(input_request, input_type,
                       tamper, output_json_file_name, uri_client, worker_obj,
                       input_method, private_key, err_cd, check_result_1)
                       
    elif input_method is "WorkOrderGetResult" :
        check_get_result = request_tup[7]

        response_tup = wo_get_result.process_work_order_get_result(
                       input_request, input_type, tamper, output_json_file_name,
                       uri_client, err_cd, work_order_id, request_id,
                       check_get_result)

    # elif (input_method == "WorkerLookUp" or "WorkerRetrieve"
    #       or "WorkerRegister" or "WorkerSetStatus") :
    #     worker_obj = request_tup[5]
    #     sig_obj = request_tup[6]
    #     check_worker_result = request_tup[7]
    #
    #     response_tup = worker_utility.process_worker_actions(input_request,
    #                    input_type, tamper, output_json_file_name, uri_client,
    #                    worker_obj, sig_obj, check_worker_result)

    elif input_method in ("WorkerUpdate", "WorkerLookUp", "WorkerRetrieve",
                          "WorkerRegister", "WorkerSetStatus"):
        worker_obj = request_tup[6]
        request_id = request_tup[7]
        check_action_result = request_tup[8]

        response_tup = worker_utility.process_worker_actions(input_request,
                       input_type, tamper, output_json_file_name, uri_client,
                       input_method, worker_obj, request_id,
                       check_action_result)

    else :
        response = process_request(uri_client, input_request,
                   output_json_file_name)
        err_cd = validate_response_code(response, check_result_1)

    return response_tup
