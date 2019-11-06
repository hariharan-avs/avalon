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
from automation_framework.work_order_submit.work_order_submit_params \
                                              import WorkOrderSubmit

import automation_framework.utilities.signature as signature

logger = logging.getLogger(__name__)

# def process_work_order(input_request, input_type, tamper, output_json_file_name,
#         uri_client, worker_obj, sig_obj, request_method, private_key, err_cd,
#         check_submit):
def process_work_order(input_request, input_type, tamper, output_json_file_name,
        uri_client, worker_obj, request_method, private_key, err_cd,
        check_submit):
    """ Function to process work order
        Read input request from string or object and process request.
        Uses WorkOrderSubmit class definition to initialize work order object.
        Triggers process_request, validate_response_code,
        Returns - error code, input_json_str1, response, processing_time,
        worker_obj, sig_obj, encrypted_session_key. """

    response = {}

    if err_cd == 0:
        #--------------------------------------------------------------------
        logger.info("------ Testing WorkOrderSubmit ------")

        if input_type == "object" :
            input_work_order = json.loads(input_request.to_string())
        else :
            # create work order request
            wo_obj = WorkOrderSubmit()
            wo_obj.add_json_values(input_request, worker_obj, private_key)

            #sign_output = wo_obj.generate_signature(private_key)

            # logger.info('''sign_output : %s \n''', sign_output)
            # sign_cd = 0
            # if sign_output is None :
            #     sign_cd = 1
            #     logger.info('''Request signing failed with 'None' response''')
            # else:
            #     if sign_output is not SignatureStatus.FAILED :
            #         input_work_order = sign_output[0]
            #     else:
            #         sign_cd = 2
            #         logger.info('''Request signing failed with
            #                     'SignatureStatus.FAILED' response''')

            # if sign_cd != 0:
            # input_work_order = wo_obj.to_string()
            input_work_order = wo_obj.compute_signature(tamper)
            logger.info('''Compute Signature complete''')

        logger.info('''Request to be submitted : %s \n''', input_work_order)
        input_json_str1 = json.loads(input_work_order)
        response = process_request(uri_client, input_json_str1,
                                   output_json_file_name)
        err_cd = validate_response_code(response, check_submit)

        work_order_id = wo_obj.get_work_order_id()

    else:
        logger.info('''ERROR: No Worker Retrieved from system.
                   Unable to proceed to process work order.''')

    response_tup = (err_cd, input_json_str1, response, wo_obj.session_key,
                    wo_obj.session_iv, wo_obj.get_encrypted_session_key())

    return response_tup

def verify_work_order_signature(response, worker_obj):

    verify_key = worker_obj.verification_key

    try:
        sig_obj = signature.ClientSignature()
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
