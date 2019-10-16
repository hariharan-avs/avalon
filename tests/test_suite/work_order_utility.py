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
import work_order.work_order_params as work_order
from shared_kv.shared_kv_interface import KvStorage
import utility.utility as enclave_helper
import utility.file_utils as futils
import workflow
from api_classes import WorkOrderSubmit

logger = logging.getLogger(__name__)

def create_work_order_request(input_json_str1, worker_obj, tamper):
    """ Function to create work order request.
        Uses input string passed from process work order function.
        Modifies empty parameters in input string.
        Returns - modified input string, work order id. """

    logger.info("-----Constructing WorkOrderSubmit------")
    
    before_sign_keys = ""
    work_order_id = ""
    
    wo_obj = WorkOrderSubmit()
    wo_obj.add_json_values(input_json_str1)

    json_rpc_request = {
            "jsonrpc": "2.0",
            "method": "WorkOrderSubmit",
            "id": id
    }

    json_rpc_request["params"] = wo_obj.get_params()
    json_rpc_request["params"]["inData"] = wo_obj.get_indata()
    json_rpc_request["params"]["outData"] = wo_obj.get_outdata()
#    work_order_obj = work_order.WorkOrderParams()
#    default_json = work_order_obj.to_string()
#
#    input_json_temp = json.loads(input_json_str1)
    
#    input_param_keys = input_json_temp["params"].keys()
#    if "before_sign" in tamper["params"].keys() :
#        before_sign_keys = tamper["params"]["before_sign"].keys()

#    for input_keys in input_param_keys :
#        if input_json_temp["params"][input_keys] == "" :
#             input_keys_value = input_json_temp["params"][input_keys]
#             if input_keys in before_sign_keys:
#                 logger.info("Forced Json input for %s with value :  %s.\n", input_keys_value)
#             else:
#                 input_json_temp["params"][input_keys] = default_json["params"][input_keys]
                 
#    input_json_str1 = json.dumps(input_json_temp)

#    before_sign_keys = ""
#    work_order_id = ""
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
    sign_output = sig_obj.generate_client_signature(input_json_str1,
    worker_obj, private_key, session_key, session_iv, encrypted_session_key)
    
    output_string = input_json_str1
    logger.info('''Output of generate client signature : %s \n ''', sign_output)
    if sign_output is None :
        err_cd = 1
    else:
        if sign_output is not SignatureStatus.FAILED :
            output_string = sign_output[0]
        else:
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
    response_timeout_multiplier = ((6000/3600) + 6) * 3
    while("result" not in response):
        if "error" in response:
            if response["error"]["code"] != 5:
                logger.info('''WorkOrderGetResult -
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

def process_work_order(input_json_str, tamper, output_json_file_name,
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
        #--------------------------------------------------------------------
        logger.info("------ Testing WorkOrderSubmit ------")

        # create work order request
        wo_obj = WorkOrderSubmit()
        wo_obj.add_json_values(input_json_str, tamper)

        json_rpc_request = {
                "jsonrpc": "2.0",
                "method": "WorkOrderSubmit",
                "id": id
        }

        json_rpc_request["params"] = wo_obj.get_params()

        in_data = wo_obj.get_indata()
        out_data = wo_obj.get_outdata()

        if in_data is not None:
                        json_rpc_request["params"]["inData"] = in_data

        if out_data is not None:
                        json_rpc_request["params"]["outData"] = out_data

        response = process_request(uri_client, json_rpc_request,
                   output_json_file_name)
        err_cd = validate_response_code(response, check_result_1)

    else:
        logger.info('''ERROR: No Worker Retrieved from system.
                   Unable to proceed to process work order.''')


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

    after_sign_keys = []
    input_json_temp = json.loads(input_json_str1)
    if "after_sign" in tamper["params"].keys():
        after_sign_keys = tamper["params"]["after_sign"].keys()
    
    for tamper_key in after_sign_keys:
        input_json_temp["params"][tamper_key] = tamper["params"]["after_sign"][tamper_key]
    
    input_json_str1 = json.dumps(input_json_temp)

    return input_json_str1

def verify_work_order_signature(response, sig_obj, worker_obj):

    verify_key = worker_obj.verification_key

    try:
        sig_bool = sig_obj.verify_signature(response, verify_key)

        logger.info("Signature return verify: %s \n", sig_bool)
        if sig_bool is SignatureStatus.PASSED :
        #if sig_bool > 0:
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
        decrypted_data = enclave_helper.decrypted_response(response,
                         session_key, session_iv)
        err_cd = 0
        logger.info('''Success: Work Order Response Decrypted''')
    except:
        err_cd = 1
        logger.info('''ERROR: Work Order Response Decryption Failed''')

    return err_cd, decrypted_data

def validate_request(request_tup):

    input_json_temp = request_tup[0]
    input_type = request_tup[1]
    tamper = request_tup[2]
    output_json_file_name = request_tup[3]
    worker_obj = request_tup[4]
    sign_obj = request_tup[5]
    uri_client = request_tup[6]
    private_key = request_tup[7]
    err_cd = request_tup[8]
    check_result_1 = request_tup[9]
    check_result_2 = request_tup[10]

    input_json_str = ""

    try :
        if input_type == "file" :
            # read json input file for the test case
            logger.info("------ Input file name: %s ------\n", input_json_temp)
        
            with open(input_json_temp, "r") as inp_file:
                input_json=json.load(inp_file)

        elif input_type == "string" :
            input_json = input_json_temp
    
        input_json_str = json.loads(input_json)
    except :
        logger.info('''Invalid Json Input. 
                Submitting to enclave without modifications to test response''')

        response = process_request(uri_client, input_json_temp, 
                   output_json_file_name)
        err_cd = validate_response_code(response, check_result_1)

    if input_json_str != "" :
        input_method = input_json_str["method"] 

        if input_method is "WorkOrderSubmit" :
            (err_cd, input_json_str, response, processing_time, 
            worker_obj, sig_obj, session_key, session_iv, 
            encrypted_session_key) = process_work_order(input_json_str, 
                    tamper, output_json_file_name,
                    worker_obj, sig_obj, uri_client, private_key, 
                    err_cd, check_result_1, check_result_2)
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
            response = process_request(uri_client, input_json_temp,
                       output_json_file_name)
            err_cd = validate_response_code(response, check_result_1)
        
    return input_json_str
