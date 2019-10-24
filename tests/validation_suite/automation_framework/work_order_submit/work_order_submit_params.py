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

        if "sessionKeyIv" in input_params_list :
            if input_json_temp["params"]["sessionKeyIv"] != "" :
                self.set_session_key_iv(
                input_json_temp["params"]["sessionKeyIv"])
            else :
                self.set_session_key_iv(byte_array_to_hex_str(
                                        self.session_iv))

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

        if "requesterNonce" in input_params_list :
            if input_json_temp["params"]["requesterNonce"] != "" :
                self.set_requester_nonce(crypto.byte_array_to_base64(
                     crypto.compute_message_hash(crypto.string_to_byte_array(
                     input_json_temp["params"]["requesterNonce"]))))
            else :
                self.set_requester_nonce(crypto.byte_array_to_base64(
                     crypto.compute_message_hash(
                     crypto.random_bit_string(NO_OF_BYTES))))

        if "encryptedRequestHash" in input_params_list :
            if input_json_temp["params"]["encryptedRequestHash"] != "" :
                self.params_obj["encryptedRequestHash"] = \
                input_json_temp["params"]["encryptedRequestHash"]

        if "requesterSignature" in input_params_list :
            if input_json_temp["params"]["requesterSignature"] != "" :
                self.params_obj["requesterSignature"] = \
                input_json_temp["params"]["requesterSignature"]

        if "verifyingKey" in input_params_list :
            if input_json_temp["params"]["verifyingKey"] != "" :
                self.params_obj["verifyingKey"] = input_json_temp["params"]["verifyingKey"]

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

    def add_encrypted_request_hash(self):
        """
        calculates request has based on EEA trusted-computing spec 6.1.8.1
        and set encryptedRequestHash parameter in the request.
        """
        sig_obj = signature.ClientSignature()
        concat_string = self.get_requester_nonce().encode('UTF-8') + \
                self.get_work_order_id().encode('UTF-8') + \
                self.get_worker_id().encode('UTF-8') + \
                self.get_workload_id().encode('UTF-8') + \
                self.get_requester_id().encode('UTF-8')
        concat_bytes = bytes(concat_string)
        #SHA-256 hashing is used
        hash_1 = crypto.byte_array_to_base64(
                crypto.compute_message_hash(concat_bytes)
        )
        hash_2 = ""
        in_data = self.get_in_data()
        if in_data and len(in_data) > 0:
            logger.info('''In indata hash loop \n''')
            hash_2 = sig_obj.calculate_datahash(in_data)

        hash_3 = ""
        out_data = self.get_out_data()
        if out_data and len(out_data) > 0:
            hash_3 = sig_obj.calculate_datahash(out_data)
        concat_hash = hash_1 + hash_2 + hash_3
        concat_hash = bytes(concat_hash, "UTF-8")
        self.final_hash = crypto.compute_message_hash(concat_hash)
        self.encrypted_request_hash = enclave_helper.encrypt_data(
                self.final_hash, self.session_key, self.session_iv)
        self.params_obj["encryptedRequestHash"] = byte_array_to_hex_str(
                self.encrypted_request_hash)

        logger.info('''Final Hash 1: %s \n''', self.final_hash)
        return self.final_hash

    def add_requester_signature(self, private_key, final_hash, tamper):
        """
        Calculate the signature of the request as defined in TCF EEA spec 6.1.8.3
        and set the requesterSignature parameter in the request
        """
        logger.info('''Final Hash 2: %s \n''', final_hash)
        sig_obj = signature.ClientSignature()

        status, sign = sig_obj.generate_signature(
                final_hash,
                private_key
        )
        if status == True:
                self.params_obj["requesterSignature"] = sign
                logger.info("Signing Populated")
                # public signing key is shared to enclave manager to verify the signature.
                # It is temporary approach to share the key with the worker.
                self.set_verifying_key(private_key.GetPublicKey().Serialize())
                return True
        else:
                logger.info("Signing request failed")
                return False

    def set_verifying_key(self, verifying_key):
        self.params_obj["verifyingKey"] = verifying_key

    def add_in_data(self, input_json_inData):
        if not "inData" in self.params_obj:
            self.params_obj["inData"] = []

        for inData_item in input_json_inData :
            logger.info('''Type of indataitem : %s \n''', type(inData_item))
            if type(inData_item) is dict :
                # logger.info('''Type of indataitem in loop : %s \n''', type(inData_item))
                # inData_item_keys = inData_item.keys()
                # logger.info('''Type of indataitem keys: %s \n''', inData_item_keys)
                # if "index" in inData_item_keys :
                #     index = inData_item["index"]
                # if "dataHash" in inData_item_keys :
                #     dataHash = inData_item["dataHash"]
                # if "data" in inData_item_keys :
                #     data = inData_item["data"]
                # if "encryptedDataEncryptionKey" in inData_item_keys :
                #     encryptedDataEncryptionKey = inData_item["encryptedDataEncryptionKey"]
                # if "iv" in inData_item_keys:
                #     data_iv = inData_item["iv"]
                #
                # logger.info('''index : %s, dataHash : %s, data : %s,
                #             encrypted_data_encryption_key : %s, iv : %s \n''',
                #             index, dataHash, data, encryptedDataEncryptionKey, data_iv)
                #     # if (input_json_inData["index"] != "" and
                #     # input_json_inData["dataHash"] == "" and
                #     # input_json_inData["data"] != "" and
                #     # input_json_inData["encryptedDataEncryptionKey"] == "" and
                #     # input_json_inData["iv"] == "") :
                # in_data_copy = self.params_obj["inData"]
                # new_data_list = self.__add_data_params(index,
                #                 in_data_copy,
                #                 data, dataHash,
                #                 encryptedDataEncryptionKey,
                #                 data_iv)
                # self.params_obj["inData"] = new_data_list
                in_data_copy = self.params_obj["inData"]
                in_data_copy.append(inData_item)
                self.params_obj["inData"] = in_data_copy
            else :
                in_data_copy = self.params_obj["inData"]
                in_data_copy.append(inData_item)
                self.params_obj["inData"] = in_data_copy

    def add_out_data(self, input_json_outData):
        if not "outData" in self.params_obj:
                self.params_obj["outData"] = []

        for outData_item in input_json_outData :
            if type(outData_item) == "dict" :
                outData_item_keys = outData_item.keys()
                if ("index", "dataHash", "data",
                "encryptedDataEncryptionKey", "iv") in outData_item_keys:
                    if (input_json_outData["index"] != "" and
                    input_json_outData["dataHash"] == "" and
                    input_json_outData["data"] == "" and
                    input_json_outData["encryptedDataEncryptionKey"] == "" and
                    input_json_outData["iv"] == "") :
                        out_data_copy = self.params_obj["outData"]
                        new_data_list = self.__add_data_params(index,
                                        out_data_copy,
                                        data, data_hash,
                                        encrypted_data_encryption_key,
                                        data_iv)
                        self.params_obj["outData"] = new_data_list
            else :
                out_data_copy = self.params_obj["outData"]
                new_data_list = out_data_copy.append(outData_item)
                self.params_obj["outData"] = new_data_list

        self.params_obj["outData"] = new_data_list

    def __add_data_params(self, index, data_items, data, data_hash,
                            encrypted_data_encryption_key, data_iv):
        logger.info('''Second Position - index : %s, dataHash : %s, data : %s,
                    encrypted_data_encryption_key : %s, iv : %s \n''',
                    index, data_hash, data, encrypted_data_encryption_key, data_iv)
        #data_items.append({"index": index, "dataHash": data_hash,
        #                   "data": data, "encryptedDataEncryptionKey":
        #                   encrypted_data_encryption_key,
        #                   "iv": data_iv})
        #data_items.append({"index": index, "dataHash": data_hash,
        #                   "data": self.__encrypt_data(data,
        #                   encrypted_data_encryption_key,
        #                   data_iv), "encrypDataEncryptionKey":
        #                   encrypted_data_encryption_key,
        #                   "iv": data_iv})
        data_items[index]["index"] = index
        data_items[index]["data"] = self.__encrypt_data(
                data,
                encrypted_data_encryption_key,
                data_iv
        )
        if data_hash:
                data_items[index]["dataHash"] = data_hash
        if encrypted_data_encryption_key:
                data_items[index]["encryptedDataEncryptionKey"] = \
                        encrypted_data_encryption_key
        if data_iv:
                data_items[index]["iv"] = data_iv
        return data_items

    # Use these if you want to pass json to WorkOrderJRPCImpl
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

    def __encrypt_data(self, data, encrypted_data_encryption_key,
            data_iv):
        data = data.encode("UTF-8")
        e_key =  encrypted_data_encryption_key.encode('UTF-8')

        if (not e_key ) or (e_key == "null".encode('UTF-8')):
            enc_data = enclave_helper.encrypt_data(data, self.session_key, self.session_iv)
            return crypto.byte_array_to_base64(enc_data)
        elif e_key == "-".encode('UTF-8'):
            # Skip encryption and just encode workorder data to base64 format
            enc_data = crypto.byte_array_to_base64(data)
            return enc_data
        else:
            enc_data = enclave_helper.encrypt_data(data, encrypted_data_encryption_key, data_iv)
            return crypto.byte_array_to_base64(enc_data)

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
