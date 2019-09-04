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
test_result = {}
test_req = ''

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def LocalMain(config) :

    global file_no
    global test_result
    global test_req

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
    if input_json_dir:
        directory = os.fsencode(input_json_dir)
        files = os.listdir(directory)

        file_no = 0

        for file in sorted(files) :
            logger.info("------------------Input file name: %s ---------------\n",file.decode("utf-8"))
            input_json_str1 = futils.read_json_file((directory.decode("utf-8") + file.decode("utf-8")))
            file_no += 1
            file_nme = file_no
            #----------------------------------------------------------------------------------

            if "WorkerUpdate" in input_json_str1 :

                response = processRequest(file_no, uri_client, input_json_str1)

                if "error" in response:
                    if response["error"]["code"] == 0:
                        err_cd = 0
                        logger.info("SUCCESS: Worker Update successfull by-passing additional unkown parameters in input")
                    else:
                        err_cd = 1
                        logger.info("ERROR: Worker Update failed due to additional unkown parameters in input")
                else:
                    err_cd = 1
                    logger.info("ERROR: Worker Update response not in expected format")

    else :
        logger.info("Input Request %s", input_json_str)
        file_no += 1
        response = processRequest(file_no, uri_client, input_json_str1)
#        response = uri_client._postmsg(input_json_str_1)
#        logger.info("Received Response : %s , \n \n ", response);

    exit(err_cd)

TCFHOME = os.environ.get("TCF_HOME", "../../")

def processRequest(file_no, uri_client, input_json_str1):

    global result_cd
    global err_cd

    req_time = time.strftime("%Y%m%d_%H%M%S")
    signed_input_file = './worker_results/' + output_json_file_name + '_' + req_time + str(file_no) + '_request.json'

    with open(signed_input_file,"w") as req_file:
        json.dump(input_json_str1, req_file)

    logger.info("**********Received Request*********\n%s\n", input_json_str1)
    response = uri_client._postmsg(input_json_str1)
    logger.info("**********Received Response*********\n%s\n", response)

    response_output_file = './worker_results/' + output_json_file_name + '_' + req_time + str(file_no) + '_response.json'

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
