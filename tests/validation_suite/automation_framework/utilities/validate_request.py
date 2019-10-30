import pytest
import json
import os
import sys
import logging
import automation_framework.utilities.file_utils as futils
import automation_framework.work_order_submit.work_order_utility as wo_utility
from automation_framework.utilities.workflow import process_request
from automation_framework.utilities.workflow import validate_response_code

logger = logging.getLogger(__name__)

def validate_request(request_tup) :

    input_json_temp = request_tup[0]
    input_type = request_tup[1]

    try :
        if input_type == "file" :
            # read json input file for the test case
            logger.info("------ Input file name: %s ------\n", input_json_temp)

            input_json = futils.read_json_file(input_json_temp)
            #with open(input_json_temp) as inp_file:
            #    input_json = json.load(inp_file)
            logger.info("------ Loaded file name: %s ------\n", input_json_temp)
        elif input_type == "string" :
            input_json = input_json_temp
    except :
        logger.info('''Invalid Json Input.
                Submitting to enclave without modifications to test response''')

        response = process_request(uri_client, input_json_temp,
                   output_json_file_name)
        err_cd = validate_response_code(response, check_result_1)

    logger.info("Json loaded : %s \n", input_json)
    input_json_str = json.loads(input_json)
    logger.info("Json Str 1 loaded : %s \n", input_json_str)
    if input_json_str != {} :

        input_method = input_json_str["method"]
        # input_json_str = json.dumps(input_json_str)
        logger.info("Json input_method : %s \n", input_method)
        logger.info("Json Str 2 loaded : %s \n", input_json_str)

        if input_method == "WorkOrderSubmit" :
            tamper = request_tup[2]
            output_json_file_name = request_tup[3]
            worker_obj = request_tup[4]
            sig_obj = request_tup[5]
            uri_client = request_tup[6]
            private_key = request_tup[7]
            err_cd = request_tup[8]
            check_result_1 = request_tup[9]
            check_result_2 = request_tup[10]

            response_tup = wo_utility.process_work_order(input_json_str, tamper,
                           output_json_file_name, worker_obj, sig_obj,
                           uri_client, private_key, err_cd, check_result_1,
                           check_result_2)
        elif input_method is "WorkOrderGetResult" :
            pass

        elif input_method is "WorkerLookUp" :
            pass

        elif input_method is "WorkerRetrieve" :
            pass

        elif input_method is "WorkerRegister" :
            pass

        elif input_method is "WorkerUpdate" :
            pass

        elif input_method is "WorkerSetStatus" :
            pass

        else :
            response = process_request(uri_client, input_json_str,
                       output_json_file_name)
            err_cd = validate_response_code(response, check_result_1)

    return response_tup
