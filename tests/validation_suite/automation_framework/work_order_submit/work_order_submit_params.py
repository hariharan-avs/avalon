import json
import logging
import os
import sys
import random

import crypto.crypto as crypto
import automation_framework.worker.worker_params as worker
import automation_framework.utilities.signature as signature
import automation_framework.utilities.utility as enclave_helper
from automation_framework.utilities.hex_utils import is_hex, byte_array_to_hex_str

logger = logging.getLogger(__name__)
NO_OF_BYTES = 16

class WorkOrderSubmit():
    def __init__(self):
        self.id_obj = {"jsonrpc": "2.0", "method": "WorkOrderSubmit", "id": 3}
        self.params_obj = {}
        self.session_key = enclave_helper.generate_key()
        self.session_iv = enclave_helper.generate_iv()

    def add_json_values(self, input_json, tamper, worker_obj):

        # input_json_temp = json.loads(input_json)
        input_json_temp = input_json
        self.worker_obj = worker_obj

        input_params_list = input_json_temp["params"].keys()
        if "responseTimeoutMSecs" in input_params_list :
            if input_json_temp["params"]["responseTimeoutMSecs"] != "" :
                self.set_response_timeout_msecs(
                input_json_temp["params"]["responseTimeoutMSecs"])
            else :
                self.set_response_timeout_msecs(6000)

        if "payloadFormat" in input_params_list :
            if input_json_temp["params"]["payloadFormat"] != "" :
                self.set_payload_format(
                input_json_temp["params"]["payloadFormat"])
            else :
                self.set_payload_format("JSON-RPC")

        if "resultUri" in input_params_list :
            if input_json_temp["params"]["resultUri"] != "" :
                self.set_result_uri(input_json_temp["params"]["resultUri"])
            else :
                self.set_result_uri("")

        if "notifyUri" in input_params_list :
            if input_json_temp["params"]["notifyUri"] != "" :
                self.set_notify_uri(input_json_temp["params"]["notifyUri"])
            else :
                self.set_notify_uri("")

        if "workOrderId" in input_params_list :
            if input_json_temp["params"]["workOrderId"] != "" :
                self.set_work_order_id(input_json_temp["params"]["workOrderId"])
            else :
                work_order_id = hex(random.randint(1, 2**64 -1))
                self.set_work_order_id(work_order_id)

        if "workerId" in input_params_list :
            if input_json_temp["params"]["workerId"] != "" :
                self.set_worker_id(input_json_temp["params"]["workerId"])
            else :
                self.set_worker_id(worker_obj.worker_id)

        if "workloadId" in input_params_list :
            if input_json_temp["params"]["workloadId"] != "" :
                self.set_workload_id(
                input_json_temp["params"]["workloadId"].encode('UTF-8').hex())
            else :
                workload_id = "echo-client"
                self.set_workload_id(workload_id.encode('UTF-8').hex())

        if "requesterId" in input_params_list :
            if input_json_temp["params"]["requesterId"] != "" :
                self.set_requester_id(input_json_temp["params"]["requesterId"])
            else :
                self.set_requester_id("0x3456")

        if "workerEncryptionKey" in input_params_list :
            if input_json_temp["params"]["workerEncryptionKey"] != "" :
                self.set_worker_encryption_key(
                input_json_temp["params"]["workerEncryptionKey"])
            else :
                self.set_worker_encryption_key("")

        if "dataEncryptionAlgorithm" in input_params_list :
            if input_json_temp["params"]["dataEncryptionAlgorithm"] != "" :
                self.set_data_encryption_algorithm(
                input_json_temp["params"]["dataEncryptionAlgorithm"])
            else :
                self.set_data_encryption_algorithm("AES-GCM-256")

        if "encryptedSessionKey" in input_params_list :
            if input_json_temp["params"]["encryptedSessionKey"] != "" :
                self.set_encrypted_session_key(
                     input_json_temp["params"]["encryptedSessionKey"])
            else :
                self.encrypted_session_key = (
                     enclave_helper.generate_encrypted_key (self.session_key,
                                    worker_obj.encryption_key))
                #self.set_encrypted_session_key(self.encrypted_session_key)
                self.set_encrypted_session_key(byte_array_to_hex_str(
                                               self.encrypted_session_key))

        if "sessionKeyIv" in input_params_list :
            if input_json_temp["params"]["sessionKeyIv"] != "" :
                self.set_session_key_iv(
                     input_json_temp["params"]["sessionKeyIv"])
            else :
                self.set_session_key_iv(byte_array_to_hex_str(
                     self.session_iv))

        if "requesterNonce" in input_params_list :
            if input_json_temp["params"]["requesterNonce"] != "" :
                self.set_requester_nonce(input_json_temp["params"]["requesterNonce"])
            else :
                self.set_requester_nonce("")

        if "encryptedRequestHash" in input_params_list :
            if input_json_temp["params"]["encryptedRequestHash"] != "" :
                self.params_obj["encryptedRequestHash"] = \
                     input_json_temp["params"]["encryptedRequestHash"]
            else :
                self.params_obj["encryptedRequestHash"] = ""

        if "requesterSignature" in input_params_list :
            if input_json_temp["params"]["requesterSignature"] != "" :
                self.params_obj["requesterSignature"] = \
                     input_json_temp["params"]["requesterSignature"]
            else :
                self.params_obj["requesterSignature"] = ""

        if "inData" in input_params_list :
            if input_json_temp["params"]["inData"] != "" :
                input_json_inData = input_json_temp["params"]["inData"]
                self.add_in_data(input_json_inData)
            else :
                self.params_obj["inData"] = ""

        if "outData" in input_params_list :
            if input_json_temp["params"]["outData"] != "" :
                input_json_outData = input_json_temp["params"]["outData"]
                self.add_out_data(input_json_outData)
            else :
                self.params_obj["outData"] = ""

        if "verifyingKey" in input_params_list :
            if input_json_temp["params"]["verifyingKey"] != "" :
                self.params_obj["verifyingKey"] = input_json_temp["params"]["verifyingKey"]
            else :
                self.params_obj["verifyingKey"] = ""

    def set_response_timeout_msecs(self, response_timeout_msecs):
            self.params_obj["responseTimeoutMSecs"] = \
                    response_timeout_msecs

    def set_payload_format(self, payload_format):
        self.params_obj["payloadFormat"] = payload_format

    def set_result_uri(self, result_uri):
        self.params_obj["resultUri"] = result_uri

    def set_notify_uri(self, notify_uri):
        self.params_obj["notifyUri"] = notify_uri

    def set_worker_id(self, worker_id):
        self.params_obj["workerId"] = worker_id

    def set_work_order_id(self, work_order_id):
        self.params_obj["workOrderId"] = work_order_id

    def set_workload_id(self, workload_id):
        self.params_obj["workloadId"] = workload_id

    def set_requester_id(self, requester_id):
        self.params_obj["requesterId"] = requester_id

    def set_worker_encryption_key(self, worker_encryption_key):
        self.params_obj["workerEncryptionKey"] = worker_encryption_key

    def set_data_encryption_algorithm(self, data_encryption_algorithm):
        self.params_obj["dataEncryptionAlgorithm"] = \
                data_encryption_algorithm

    def set_encrypted_session_key(self, encrypted_session_key):
        self.params_obj["encryptedSessionKey"] = encrypted_session_key

    def set_session_key_iv(self, session_iv):
        self.params_obj["sessionKeyIv"] = session_iv

    def set_requester_nonce(self, requester_nonce):
        self.params_obj["requesterNonce"] = requester_nonce

    def add_encrypted_request_hash(self, encrypted_request_hash):
        self.params_obj["encryptedRequestHash"] = encrypted_request_hash

    def add_requester_signature(self, requester_signature):
        self.params_obj["requesterSignature"] = requester_signature

    def set_verifying_key(self, verifying_key):
        self.params_obj["verifyingKey"] = verifying_key

    def add_in_data(self, input_json_inData):
        if not "inData" in self.params_obj:
            self.params_obj["inData"] = []

        for inData_item in input_json_inData :
            in_data_copy = self.params_obj["inData"]
            in_data_copy.append(inData_item)
            self.params_obj["inData"] = in_data_copy

    def add_out_data(self, input_json_outData):
        if not "outData" in self.params_obj:
                self.params_obj["outData"] = []

        for outData_item in input_json_outData :
            out_data_copy = self.params_obj["outData"]
            new_data_list = out_data_copy.append(outData_item)
            self.params_obj["outData"] = new_data_list

    def get_params(self):
        params_copy = self.params_obj.copy()
        if "inData" in params_copy:
            params_copy.pop("inData")
        if "outData" in params_copy:
            params_copy.pop("outData")
        return params_copy

    def get_in_data(self):
        if "inData" in self.params_obj:
            return self.params_obj["inData"]
        else :
            return None

    def get_out_data(self):
        if "outData" in self.params_obj:
            return self.params_obj["outData"]
        else :
            return None

    def get_requester_nonce(self):
        return self.params_obj["requesterNonce"]

    def get_worker_id(self):
        return self.params_obj["workerId"]

    def get_workload_id(self):
        return self.params_obj["workloadId"]

    def get_requester_id(self):
        return self.params_obj["requesterId"]

    def get_session_key_iv(self):
        return self.params_obj["sessionKeyIv"]

    def get_work_order_id(self):
        return self.params_obj["workOrderId"]

    def get_encrypted_session_key(self):
        return self.params_obj["encryptedSessionKey"]

    def get_encrypted_request_hash(self):
        if "encryptedRequestHash" in self.params_obj:
            return self.params_obj["encryptedRequestHash"]
        else :
            return None

    def get_requester_signature(self):
        if "requesterSignature" in self.params_obj:
            return self.params_obj["requesterSignature"]
        else :
            return None

    def to_string(self):
        json_rpc_request = self.id_obj
        json_rpc_request["params"] = self.get_params()

        in_data = self.get_in_data()
        out_data = self.get_out_data()

        if in_data is not None:
            json_rpc_request["params"]["inData"] = in_data

        if out_data is not None:
            json_rpc_request["params"]["outData"] = out_data

        return json.dumps(json_rpc_request, indent=4)

    def generate_signature(self, private_key, tamper):

        sig_obj = signature.ClientSignature()
        data_key = None
        data_iv = None
        sign_result = sig_obj.generate_client_signature(self.to_string(),
                self.worker_obj, private_key, self.session_key, self.session_iv,
                self.encrypted_session_key,
                data_key, data_iv, tamper)

        return sign_result
