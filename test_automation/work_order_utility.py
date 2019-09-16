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
import crypto.crypto as crypto
import utility.signature as signature
import worker.worker_details as worker
from shared_kv.shared_kv_interface import KvStorage
import utility.utility as enclave_helper
import utility.file_utils as futils
import workflow

logger = logging.getLogger(__name__)

def create_work_order_request(input_json_str1, worker_obj, tamper):
    """ Function to create work order request.
        Uses input string passed from process work order function.
        Modifies empty parameters in input string.
        Returns - modified input string, work order id. """

    logger.info("-----Constructing WorkOrderSubmit------")

    before_sign_keys = ""
    work_order_id = ""
    input_json_temp = json.loads(input_json_str1)
    if "before_sign" in tamper["params"].keys():
        before_sign_keys = tamper["params"]["before_sign"].keys()
    # get request_id from input
    request_id = input_json_temp["id"]

    # compute work order id
    work_order_id_json = input_json_temp["params"]["workOrderId"]
    if "workOrderId" in before_sign_keys:
        logger.info("Forced Json input work order id %s.\n", work_order_id_json)
        work_order_id = work_order_id_json
    else:
        if work_order_id_json == "":
            work_order_id = hex(random.randint(1, 2**64 -1))
            input_json_temp["params"]["workOrderId"] = work_order_id
        else:
            work_order_id = work_order_id_json

    # compute worker id
    worker_id_json = input_json_temp["params"]["workerId"]
    if "workerId" in before_sign_keys:
        logger.info("Forced Json input worker id %s.\n", worker_id_json)
        worker_obj.worker_id = worker_id_json
    else:
        if worker_id_json == "":
            input_json_temp["params"]["workerId"] = worker_obj.worker_id

    # Convert workloadId to a hex string and update the request
    workload_id = input_json_temp["params"]["workloadId"]
    if "workloadId" in before_sign_keys:
        logger.info("Forced Json input workload id %s.\n", workload_id)
    else:
        workload_id_hex = workload_id.encode("UTF-8").hex()
        input_json_temp["params"]["workloadId"] = workload_id_hex
    input_json_str1 = json.dumps(input_json_temp)

    return input_json_str1

def sign_work_order_request(input_json_str1, worker_obj, sig_obj, private_key):
    """ Function to sign the work order request. """

    logger.info("----- Signing WorkOrderSubmit -----")
    err_cd = 0
    # create session_iv through enclave_helper
    session_iv = enclave_helper.generate_iv()
    session_key = enclave_helper.generate_key()
    # create encrypted_session_key from session_iv and worker_encryption_key
    encrypted_session_key = (enclave_helper.generate_encrypted_key
    (session_key, worker_obj.encryption_key))
    # sign work order submit request
    output_string = sig_obj.generate_client_signature(input_json_str1,
    worker_obj, private_key, session_key, session_iv, encrypted_session_key)

    if output_string == SignatureStatus.FAILED:
        err_cd = 2

    return err_cd, output_string, session_key, session_iv, encrypted_session_key

def create_work_order_get_result(work_order_id, request_id):
    """ Function to create work order get result request. """

    logger.info("----- Constructing WorkOrderGetResult -----")
    # create work order get result request
    input_workorder_getresult = '''{"jsonrpc": "2.0",
                                "method": "WorkOrderGetResult","id": 11,
                                "params": {"workOrderId": ""}}'''

    input_json_temp = json.loads(input_workorder_getresult)
    input_json_temp["params"]["workOrderId"] = work_order_id
    input_json_temp["id"] = request_id
    input_json_str1 = json.dumps(input_json_temp)

    return input_json_str1

def process_work_order_get_result(work_order_id, request_id,
                                 response_timeout, uri_client):
    """ Function to process work order get result response. """

    # process work order get result and retrieve response
    input_json_str1 = create_work_order_get_result(work_order_id, request_id)
    logger.info("----- Validating WorkOrderGetResult Response ------")
    response = {}
    output_json_file_name = 'work_order_get_result'

    response_timeout_start = time.time()
    response_timeout_multiplier = ((response_timeout/3600) + 6) * 3
    while("result" not in response):
        if "error" in response:
            if response["error"]["code"] != 5:
                logger.info('''ERROR: Failed at WorkOrderGetResult -
                             Response received with error code. ''')
                err_cd = 1
                break

        response_timeout_end = time.time()
        if (response_timeout_end - response_timeout_start) > (response_timeout_multiplier):
            logger.info('''ERROR: WorkOrderGetResult response is not received
            within expected time.''')
            break

        response = workflow.process_request(uri_client, input_json_str1,
                   output_json_file_name)
        time.sleep(3)

    return response

def process_work_order(input_json, input_type, tamper, output_json_file_name,
        worker_obj, sig_obj, uri_client, private_key, err_cd, check_submit,
        check_get_result):
    """ Function to process work order
        Read input json file or use input string.
        Triggers create_work_order_request , sign_work_order_request,
        process_request, tamper_request, validate_response_code,
        process_work_order_get_result.
        Returns - error code, input_json_str1, response, processing_time,
        worker_obj, sig_obj, encrypted_session_key. """

    processing_time = ""
    response = ""

    if err_cd == 0:
        if input_type == "file":
            # read json input file for the test case
            logger.info("------ Input file name: %s ------\n", input_json)
            input_json_str1 = futils.read_json_file(input_json)
        elif input_type == "string":
            input_json_str1 = input_json
        #--------------------------------------------------------------------
        logger.info("------ Testing WorkOrderSubmit ------")

        # create work order request
        input_json_str1 = create_work_order_request(input_json_str1,
                                                   worker_obj, tamper)
        input_json_temp = json.loads(input_json_str1)
        work_order_id = input_json_temp["params"]["workOrderId"]
        request_id = input_json_temp["id"]
        response_timeout = input_json_temp["params"]["responseTimeoutMSecs"]
        input_json_str1 = json.dumps(input_json_temp)
        # sign work order request
        (err_cd, input_json_str1, session_key, session_iv,
        encrypted_session_key) = sign_work_order_request(input_json_str1,
                                      worker_obj, sig_obj, private_key)
    else:
        logger.info('''ERROR: No Worker Retrieved from system.
                   Unable to proceed to process work order.''')

    if err_cd == 0:
        # submit work order request and retrieve response
        start_wait_time = time.time()
        input_json_str1 = tamper_request(input_json_str1, tamper)
        response = workflow.process_request(uri_client, input_json_str1,
                                           output_json_file_name)
        # validate work order submit response error or result code
        err_cd = workflow.validate_response_code(response, check_submit)
    else:
        logger.info('''ERROR: WorkOrderSubmit signing process failed.
                   Hence WorkOrderSubmit not submitted to enclave.''')

    if err_cd == 0:
        logger.info("------ Testing WorkOrderGetResult ------")
        # submit work order get result request and retrieve response
        response = process_work_order_get_result(work_order_id,
                                    request_id, response_timeout, uri_client)
        end_wait_time = time.time()
        processing_time = end_wait_time - start_wait_time
        # validate work order get result code response error or result code
        err_cd = workflow.validate_response_code(response, check_get_result)
    else:
        logger.info('''ERROR: WorkOrderGetResult not performed -
                    as expected response not received for
                    WorkOrderSubmit.''')

    return (err_cd, input_json_str1, response, processing_time, worker_obj,
        sig_obj, session_key, session_iv, encrypted_session_key)

def tamper_request(input_json_str1, tamper):

    input_json_temp = json.loads(input_json_str1)
    if "requesterSignature" in tamper["params"].keys():
        input_json_temp["params"]["requesterSignature"] = ""
    if "workerId" in tamper["params"].keys():
        input_json_temp["params"].pop("workerId", None)
    input_json_str1 = json.dumps(input_json_temp)

    return input_json_str1

def verify_work_order_signature(response, sig_obj, worker_obj):

    try:
        sig_bool = sig_obj.verify_signature(json.dumps(response), worker_obj)
        if sig_bool > 0:
            err_cd = 0
            logger.info('''Success: Work Order Signature Verified''')
        else:
            err_cd = 1
            logger.info('''ERROR: Work Order Signature Verification Failed''')
    except:
        err_cd = 1
        logger.error('''ERROR: Failed to analyze Signature Verification''')

    return err_cd

def decrypt_work_order_response(response, session_key, session_iv):
    decrypted_data = ""
    try:
        decrypted_data = enclave_helper.decrypted_response(json.dumps(response),
                         session_key, session_iv)
        err_cd = 0
        logger.info('''Success: Work Order Response Decrypted''')
    except:
        err_cd = 1
        logger.info('''ERROR: Work Order Response Decryption Failed''')

    return err_cd, decrypted_data
