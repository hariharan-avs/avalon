import pytest
import subprocess
import time
import os
import sys
import argparse
import random
import json
import logging

import automation_framework.utilities.config as pconfig
from automation_framework.utilities.utility import GenericServiceClient
import utility.logger as plogger
import crypto.crypto as crypto
import automation_framework.utilities.signature as signature
import automation_framework.worker.worker_params as worker
from automation_framework.worker_lookup.worker_lookup_params import WorkerLookUp
from automation_framework.worker_retrieve.worker_retrieve_params import WorkerRetrieve
import automation_framework.utilities.utility as enclave_helper
import automation_framework.utilities.file_utils as futils
from automation_framework.utilities.workflow import process_request
from automation_framework.utilities.workflow import validate_response_code

TCFHOME = os.environ.get("TCF_HOME", "../../")
logger = logging.getLogger(__name__)

@pytest.fixture(scope="session", autouse=True)
def setup_config(args=None):
    """ Fixture to setup initial config for pytest session. """

    # parse out the configuration file first
    conffiles = [ "tcs_config.toml" ]
    confpaths = [ ".", TCFHOME + "/config", "../../etc"]

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="configuration file", nargs = "+")
    parser.add_argument("--config-dir", help="configuration folder",
                         nargs = "+")
    parser.add_argument("--connect_uri", action="store",
                         default="http://localhost:1947", help="server uri")
    (options, remainder) = parser.parse_known_args(args)

    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    if options.connect_uri :
        server_uri = options.connect_uri

    try :
        config = pconfig.parse_configuration_files(conffiles, confpaths)
        config_json_str = json.dumps(config, indent=4)
    except pconfig.ConfigurationException as e :
        logger.error(str(e))
        sys.exit(-1)

    plogger.setup_loggers(config.get("Logging", {}))
    sys.stdout = plogger.stream_to_logger((logging.getLogger("STDOUT"),
                                           logging.DEBUG))
    sys.stderr = plogger.stream_to_logger((logging.getLogger("STDERR"),
                                           logging.WARN))

    logger.info("configuration for the session: %s", config)
    uri_client = GenericServiceClient(server_uri)

    sig_obj, worker_obj, private_key = initialize_objects(config, remainder)
    worker_obj, err_cd = worker_lookup_retrieve(config, worker_obj, uri_client)

    return worker_obj, sig_obj, uri_client, private_key, err_cd

def initialize_objects(config, args):
    """ Function to initialize common objects for tests. """

    logger.info('***** INTEL TRUSTED COMPUTE FRAMEWORK (TCF) *****')

    # private_key of client
    private_key = enclave_helper.generate_signing_keys()

    # Initializing Signature object, Worker Object
    sig_obj = signature.ClientSignature()
    worker_obj = worker.SGXWorkerDetails()

    # Log computed objects
    logger.info("sig_obj: %s", sig_obj)
    logger.info("worker_obj: %s", worker_obj)

    return sig_obj, worker_obj, private_key

def worker_lookup_retrieve(config, worker_obj, uri_client):
    """ Function for computing worker lookup and retrieve once per session. """

    if not uri_client:
        logger.error("Server URI is not provided")
        exit(1)

    # logger.info("Execute work order")
    response = None

    err_cd = 0
    #----------------------------------------------------------------------
    # create worker lookup request
    output_json_file_name = 'worker_lookup'
    # input_worker_look_up = '''{"jsonrpc": "2.0", "method": "WorkerLookUp",
    #                         "id": 1, "params": {"workerType": 1}}'''
    # input_worker_look_up = {
    #         "jsonrpc": "2.0",
    #         "method": "WorkerLookUp",
    #         "id": 1
    # }
    #
    # input_worker_look_up["params"] = {
    #         "workerType": 1
    # }

    lookup_obj = WorkerLookUp()
    lookup_obj.set_worker_type(1)
    input_worker_look_up = json.loads(lookup_obj.to_string())

    # input_json_str = input_worker_look_up
    logger.info("------------------Testing WorkerLookUp------------------")

    # submit worker lookup request and retrieve response
    logger.info("********Received Request*******\n%s\n", input_worker_look_up)
    response = process_request(uri_client, input_worker_look_up,
                               output_json_file_name)
    logger.info("**********Received Response*********\n%s\n", response)

    # check worker lookup response
    if "result" in response and "totalCount" in response["result"].keys():
        if response["result"]["totalCount"] == 0:
            err_cd = 1
            logger.info('''ERROR: Failed at WorkerLookUp -
                    No Workers exist to process workorder.''')

    if err_cd == 0:
        # create worker retrieve request
        # input_worker_retrieve = '''{"jsonrpc": "2.0", "method": "WorkerRetrieve"
        #                         , "id": 2, "params": {"workerId": ""}}'''
        # input_json_str1 = json.loads(input_worker_retrieve)

        # input_worker_retrieve = {
        #         "jsonrpc": "2.0",
        #         "method": "WorkerRetrieve",
        #         "id": 2
        # }
        #
        # input_worker_retrieve["params"] = {
        #         "workerId": ""
        # }

        retrieve_obj = WorkerRetrieve()

        logger.info("-----Testing WorkerRetrieve-----")
        # Retrieving the worker id from the "WorkerLookUp" response and
        # update the worker id information for the further json requests
        if "result" in response and "ids" in response["result"].keys():
                #input_json_final = input_json_str1
                #input_json_final["params"]["workerId"] = (enclave_helper.
                #strip_begin_end_key(response["result"]["ids"][0]))
                retrieve_obj.set_worker_id(enclave_helper.
                strip_begin_end_key(response["result"]["ids"][0]))
                input_worker_retrieve = json.loads(retrieve_obj.to_string())
                # input_worker_retrieve["params"]["workerId"] = (enclave_helper.
                # strip_begin_end_key(response["result"]["ids"][0]))
                #input_json_str1 = json.dumps(input_json_final)

                logger.info('''*****Worker details Updated with Worker ID*****
                           \n%s\n''', input_worker_retrieve)
        else:
            logger.info('''ERROR: Failed at WorkerLookUp -
                       No Worker ids in WorkerLookUp response.''')
            err_cd = 1

        if err_cd == 0:
            # submit worker retrieve request and load to worker object
            response = process_request(uri_client, input_worker_retrieve,
                                      output_json_file_name)
            worker_obj.load_worker(response)

    return worker_obj, err_cd