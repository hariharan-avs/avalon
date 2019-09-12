import pytest
import time
import os
import sys
import argparse
import random
import json
import logging

from service_client.generic import GenericServiceClient
import crypto.crypto as crypto
import utility.signature as signature
import worker.worker_details as worker
from shared_kv.shared_kv_interface import KvStorage
import utility.utility as enclave_helper
import utility.file_utils as futils
from workflow import process_request
from workflow import validate_response_code

logger = logging.getLogger(__name__)

def process_worker_actions(input_json_file, id_gen, output_json_file_name,
                          worker_obj, uri_client, check_worker_result):
    ''' Function to process worker actions.
        Reads input json file of the test case.
        Triggers create worker request, process request and validate response.
        Input Parameters : input_json_file, id_gen, output_json_file_name,
        worker_obj, uri_client, check_worker_result
        Returns : err_cd, worker_obj, input_json_str1, response. '''

    # read json input file for the test case
    logger.info("----- Input file name: %s -----\n",
               input_json_file)
    input_json_str1 = futils.read_json_file(input_json_file)

    logger.info("----- Testing Worker Actions -----")

    # create work order request
    input_json_str1, worker_obj = create_worker_request(input_json_str1,
                                                       worker_obj, id_gen)
    # submit work order request and retrieve response
    response = process_request(uri_client, input_json_str1,
                              output_json_file_name)
    # validate work order response and get error code
    err_cd = validate_response_code(response, check_worker_result)

    return err_cd, worker_obj, input_json_str1, response

def create_worker_request(input_json_str1, worker_obj, id_gen):
    ''' Function to populate parameters in input string.
        Input Parameters : input_json_str1, worker_obj, id_gen
        Returns : input_json_str1, worker_obj. '''

    input_json_temp = json.loads(input_json_str1)
    if "workerId" in input_json_temp["params"].keys():
        if input_json_temp["params"]["workerId"] == "":
            if id_gen is True:
                worker_id_gen = hex(random.randint(1, 2**16 - 1))
                input_json_temp["params"]["workerId"] = worker_id_gen
                worker_obj.worker_id = worker_id_gen
            else:
                input_json_temp["params"]["workerId"] = worker_obj.worker_id
    else:
        logger.info("No parameters modified from input json.")

    input_json_str1 = json.dumps(input_json_temp)

    return input_json_str1, worker_obj
