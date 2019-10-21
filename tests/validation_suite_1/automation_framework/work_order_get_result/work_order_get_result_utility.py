import pytest
import time
import os
import sys
import argparse
import random
import json
import logging

from service_client.generic import GenericServiceClient
from error_code.error_status import SignatureStatus
import work_order.work_order_params as work_order
import utility.utility as enclave_helper
import automation_framework.utilities.file_utils as futils
from automation_framework.utilities.workflow import process_request
from automation_framework.utilities.workflow import validate_response_code

logger = logging.getLogger(__name__)

def create_work_order_get_result(work_order_id, request_id):
    """ Function to create work order get result request. """

    logger.info("----- Constructing WorkOrderGetResult -----")
    # create work order get result request
    input_workorder_getresult = '''{"jsonrpc": "2.0",
                                "method": "WorkOrderGetResult","id": 11,
                                "params": {"workOrderId": ""}}'''

    input_workorder_getresult = {
            "jsonrpc": "2.0",
            "method": "WorkOrderGetResult",
            "id": 4
    }

    input_workorder_getresult["params"] = {
            "workOrderId": work_order_id
    }
    # input_json_temp = json.loads(input_workorder_getresult)
    # input_json_temp["params"]["workOrderId"] = work_order_id
    # input_json_temp["id"] = request_id
    # input_json_str1 = json.dumps(input_json_temp)

    return input_workorder_getresult

def process_work_order_get_result(uri_client, input_json_str, tamper_get_result,
                                 work_order_id, request_id, check_get_result):
    """ Function to process work order get result response. """

    logger.info("------ Testing WorkOrderGetResult ------")
    # process work order get result and retrieve response
    input_json_str = create_work_order_get_result(work_order_id, request_id)
    logger.info("----- Validating WorkOrderGetResult Response ------")
    response = {}
    output_json_file_name = 'work_order_get_result'

    response_timeout_start = time.time()
    response_timeout_multiplier = ((6000/3600) + 6) * 3
    while("result" not in response):
        if "error" in response:
            if response["error"]["code"] != 5:
                logger.info('''WorkOrderGetResult -
                           Response received with error code. ''')
                err_cd = 1
                break

        response_timeout_end = time.time()
        if ((response_timeout_end - response_timeout_start) >
            (response_timeout_multiplier)):
            logger.info('''ERROR: WorkOrderGetResult response is not
                       received within expected time.''')
            break

        # submit work order get result request and retrieve response
        response = process_request(uri_client, input_json_str,
                   output_json_file_name)
        time.sleep (3)

    # validate work order get result code response error or result code
    err_cd = validate_response_code(response, check_get_result)
    #else:
    #    logger.info('''ERROR: WorkOrderGetResult not performed -
    #                Expected response not received for WorkOrderSubmit.''')

    return response, err_cd
