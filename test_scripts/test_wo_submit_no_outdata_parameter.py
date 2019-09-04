# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import time
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

logger = logging.getLogger(__name__)
file_no = 0
result_cd = 0
err_cd = 0

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def LocalMain(config) :

    global file_no
    global input_workorder
    global input_worker_look_up
    global input_worker_retrieve
    global input_workorder_getresult

    if not input_json_str and not input_json_dir:
       logger.error("JSON input file is not provided")
       exit(1)

    if not output_json_file_name:
        logger.error("JSON output file is not provided")
        exit(1)

    if not server_uri:
        logger.error("Server URI is not provided")
        exit(1)

    logger.info("Execute work order")
    uri_client = GenericServiceClient(server_uri)
    response = None
    wo_id = None
    request = 1

    if input_json_dir:
        directory = os.fsencode(input_json_dir)
        files = os.listdir(directory)

        err_cd = 0
        file_no = 0

        for file in sorted(files) :
            logger.info("------------------Input file name: %s ---------------\n",file.decode("utf-8"))
            input_json_str1 = futils.read_json_file((directory.decode("utf-8") + file.decode("utf-8")))
            #----------------------------------------------------------------------------------
            #input_json_str1 = json.dumps(input_worker_look_up, separators=(',', ':'))
            #input_json_str1 = json.dumps(json.dumps(input_worker_look_up))

            if "WorkerLookUp" in input_json_str1:
                logger.info("------------------Testing WorkerLookUp------------------")
                file_no += 1
                response = processRequest(file_no, uri_client, input_json_str1)

                if "result" in  response and "totalCount" in response["result"].keys() and "WorkerLookUp" in input_json_str1:
                    if response["result"]["totalCount"] == 0:
                        err_cd = 1
                        logger.info("ERROR: Failed at WorkerLookUp - No Workers exist to process workorder.")

            if "WorkerRetrieve" in input_json_str1 and err_cd == 0:
                logger.info("------------------Testing WorkerRetrieve------------------")
                #Retrieving the worker id from the "WorkerLookUp" response and update the worker id information for the further json requests
                if "result" in response and "ids" in response["result"].keys() and err_cd == 0:
                        input_json_final = json.loads(input_json_str1)
                        input_json_final["params"]["workerId"] = enclave_helper.strip_begin_end_key(response["result"]["ids"][0])
                        input_json_str1 = json.dumps(input_json_final)
                        #input_json_str1 = json.dumps(input_worker_retrieve, separators=(',', ':'))
                        logger.info("**********Worker details Updated with Worker ID*********\n%s\n", input_json_str1)
                else:
                    logger.info("ERROR: Failed at WorkerLookUp - No Worker ids in WorkerLookUp response.")
                    err_cd = 1

                if err_cd == 0:
                    file_no += 1
                    response = processRequest(file_no, uri_client, input_json_str1)
                    worker_obj.load_worker(response)

            if "WorkOrderSubmit" in input_json_str1 and err_cd == 0:
                logger.info("------------------Testing WorkOrderSubmit------------------")

                input_json_final = json.loads(input_json_str1)
                work_order_id = hex(random.randint(1, 2**10))
                input_json_final["params"]["workOrderId"] = work_order_id
                input_json_final["params"]["workerId"] = worker_obj.worker_id
                # Convert workloadId to a hex string and update the request
                workload_id = input_json_final["params"]["workloadId"]
                workload_id_hex = workload_id.encode("UTF-8").hex()
                input_json_final["params"]["workloadId"] = workload_id_hex

                inp_response_timeout = input_json_final["params"]["responseTimeoutMSecs"] / 1000
                inp_worker_id = input_json_final["params"]["workerId"]
                inp_worker_order_id = input_json_final["params"]["workOrderId"]
                inp_workload_id = input_json_final["params"]["workloadId"]
                inp_requester_id = input_json_final["params"]["requesterId"]
                input_json_str1 = json.dumps(input_json_final)

                session_iv = enclave_helper.generate_sessioniv()
                encrypted_session_key = enclave_helper.generate_encrypted_session_key(session_iv, worker_obj.worker_encryption_key)

                input_json_str1 = sig_obj.generate_client_signature(input_json_str1, worker_obj, private_key, session_iv, encrypted_session_key)

                file_no += 1
                response = processRequest(file_no, uri_client, input_json_str1)

                if response["error"]["code"] == 5:
                    err_cd = 0
                else:
                    logger.info("ERROR: Failed at WorkOrderSubmit - Request not submitted successfully.")
                    err_cd = 1

            if "WorkOrderGetResult" in input_json_str1 and err_cd == 0:
                logger.info("------------------Testing WorkOrderGetResult------------------")
                input_json_final = json.loads(input_json_str1)
                input_json_final["params"]["workOrderId"] = work_order_id
                input_json_str1 = json.dumps(input_json_final)

                while("WorkOrderGetResult" in input_json_str1 and "result" not in response):
                    if response["error"]["code"] == 9:
                        logger.info("ERROR: Failed at WorkOrderGetResult - Response received with error code 9.")
                        err_cd = 1
                        break

                    file_no += 1
                    response = processRequest(file_no, uri_client, input_json_str1)
                    time.sleep(3)

                if "result" in response and "outData" in response["result"].keys() and "code" not in response["result"].keys() and err_cd == 0:
                    logger.info("SUCCESS: WorkOrder Processed Successfully and outData in response as expected.")
                    err_cd = 0
                else:
                    err_cd = 1
                    logger.info("ERROR: WorkOrder not Processed Successfully.")

    else :
        logger.info("Input Request %s", input_json_str)
        file_no += 1
        response = processRequest(file_no, uri_client, input_json_str1)

    exit(err_cd)

TCFHOME = os.environ.get("TCF_HOME", "../../")

def processRequest(file_no, uri_client, input_json_str1):

    global result_cd
    global err_cd

    req_time = time.strftime("%Y%m%d_%H%M%S")
    signed_input_file = './workorder_results/' + output_json_file_name + req_time + str(file_no) + '_request.json'

    with open(signed_input_file,"w") as req_file:
        json.dump(input_json_str1, req_file)

    response = uri_client._postmsg(input_json_str1)
    logger.info("**********Received Response*********\n%s\n", response)

    response_output_file = './workorder_results/' + output_json_file_name + req_time + str(file_no) + '_response.json'

    with open(response_output_file,"w") as resp_file:
        json.dump(response, resp_file)

    return response

# ------------------------------------------------------------------------------------
def ParseCommandLine(config, args) :
    logger.info('***************** INTEL TRUSTED COMPUTE FRAMEWORK (TCF)*****************')
    global input_json_str
    global input_json_dir
    global server_uri
    global output_json_file_name
    global consensus_file_name
    global sig_obj
    global worker_obj
    global private_key
    global encrypted_session_key
    global session_iv

    parser = argparse.ArgumentParser()
    parser.add_argument("--logfile", help="Name of the log file, __screen__ for standard output", type=str)
    parser.add_argument("-p", "--private_key",help="Private Key of the Client", type=str, default=None)
    parser.add_argument("--loglevel", help="Logging level", type=str)
    parser.add_argument("-i", "--input_file", help="JSON input file name", type=str, default="input.json")
    parser.add_argument("--input_dir", help="Logging level", type=str, default=[])
    parser.add_argument(
        "-c", "--connect_uri", help="URI to send requests to", type=str, default=[])
    parser.add_argument(
        "output_file",
        help="JSON output file name",
        type=str,
        default="output.json",
        nargs="?")

    options = parser.parse_args(args)

    if config.get("Logging") is None :
        config["Logging"] = {
            "LogFile" : "__screen__",
            "LogLevel" : "INFO"
        }
    if options.logfile :
        config["Logging"]["LogFile"] = options.logfile
    if options.loglevel :
        config["Logging"]["LogLevel"] = options.loglevel.upper()

    input_json_str = None
    input_json_dir = None

    if options.connect_uri:
        server_uri = options.connect_uri
    else:
        logger.error("ERROR: Please enter the server URI")

    if options.input_dir:
        logger.info("Load Json Directory from %s",options.input_dir)
        input_json_dir = options.input_dir
    elif options.input_file:
        try:
            logger.info("load JSON input from %s", options.input_file)
            with open(options.input_file, "r") as file:
                input_json_str = file.read()
        except:
            logger.error("ERROR: Failed to read from file %s", options.input_file)
    else :
        logger.info("No input found")

    if options.output_file:
        output_json_file_name = options.output_file
    else:
        output_json_file_name = None

    if options.private_key:
        private_key = options.private_key
    else:
        #Generating the private Key for the client
        private_key = enclave_helper.generate_signing_keys()

    # Initializing Signature object, Worker Object
    sig_obj = signature.ClientSignature()
    worker_obj = worker.WorkerDetails()

    # -----------------------------------------------------------------
def Main(args=None):
    import config.config as pconfig
    import utility.logger as plogger

    # parse out the configuration file first
    conffiles = [ "tcs_config.toml" ]
    confpaths = [ ".", TCFHOME + "/config", "../../etc"]

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="configuration file", nargs = "+")
    parser.add_argument("--config-dir", help="configuration folder", nargs = "+")
    (options, remainder) = parser.parse_known_args(args)

    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    try :
        config = pconfig.parse_configuration_files(conffiles, confpaths)
        config_json_str = json.dumps(config, indent=4)
    except pconfig.ConfigurationException as e :
        logger.error(str(e))
        sys.exit(-1)

    plogger.setup_loggers(config.get("Logging", {}))
    sys.stdout = plogger.stream_to_logger(logging.getLogger("STDOUT"), logging.DEBUG)
    sys.stderr = plogger.stream_to_logger(logging.getLogger("STDERR"), logging.WARN)

    ParseCommandLine(config, remainder)
    LocalMain(config)

#------------------------------------------------------------------------------
Main()
