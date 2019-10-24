import pytest
import time
import os
import sys
import argparse
import random
import json
import logging

from error_code.error_status import SignatureStatus
import automation_framework.worker.worker_params as worker
import automation_framework.utilities.utility as enclave_helper
import automation_framework.utilities.file_utils as futils
from automation_framework.utilities.workflow import process_request
from automation_framework.utilities.workflow import validate_response_code
from automation_framework.work_order_submit.work_order_submit_params import WorkOrderSubmit
import automation_framework.work_order_get_result.work_order_get_result_utility as wo_get_result

logger = logging.getLogger(__name__)

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
        wo_obj.add_json_values(input_json_str, tamper, worker_obj)

        sign_output = wo_obj.generate_signature(private_key, tamper)
        
        logger.info('''sign_output : %s \n''', sign_output)
        if sign_output is None :
            err_cd = 1
        else:
            if sign_output is not SignatureStatus.FAILED :
                output_string = sign_output[0]
            else:
                err_cd = 2
                
        #if wo_obj.get_encrypted_request_hash() is not "" or None :
        #    final_hash = wo_obj.add_encrypted_request_hash()
        
        #if wo_obj.get_requester_signature() is not "" or None :
        #    wo_obj.add_requester_signature(private_key, final_hash, tamper)
        
        #output_string = wo_obj.to_string()

        logger.info('''Json RPC signed : %s \n''', output_string)
        input_json_str1 = json.loads(output_string)
        response = process_request(uri_client, input_json_str1,
                                   output_json_file_name)
        err_cd = validate_response_code(response, check_submit)

        work_order_id = wo_obj.get_work_order_id()
        request_id = 4

    else:
        logger.info('''ERROR: No Worker Retrieved from system.
                   Unable to proceed to process work order.''')

    if err_cd == 0:
        input_json_str = {}
        tamper_get_result = {}

        (response,
         err_cd) = wo_get_result.process_work_order_get_result(uri_client,
                   json.dumps(input_json_str), tamper_get_result,
                   work_order_id, request_id, check_get_result)
    else:
        logger.info('''ERROR: WorkOrderGetResult not performed -
                    Expected response not received for
                    WorkOrderSubmit.''')

    response_tup = (err_cd, input_json_str1, response, processing_time,
                    wo_obj.session_key, wo_obj.session_iv,
                    wo_obj.get_encrypted_session_key())

    return response_tup

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
