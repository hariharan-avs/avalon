import base64
import os
import sys
import json
import urllib.request
import urllib.error
import random
import json
import logging
import crypto.crypto as crypto

import automation_framework.utilities.utility as enclave_helper
from automation_framework.utilities.hex_utils import is_hex, byte_array_to_hex_str
import automation_framework.worker.worker_params as worker
from error_code.error_status import SignatureStatus

def verify_signature(input_json, verification_key):
    """
    Function to verify the signature received from the enclave
    Parameters:
        - input_json is dictionary contains payload returned by the
          Worker Service in response to successful workorder submit request
          as per TCF API 6.1.2 Work Order Result Payload
        - verification_key is ECDSA/SECP256K1 public key used to verify signatures
          created by the Enclave
    Returns enum type SignatureStatus
    """

    input_json_params = input_json['result']

    nonce = (input_json_params['workerNonce']).encode('UTF-8')
    signature = input_json_params['workerSignature']

    hash_string_1 = self.__calculate_hash_on_concatenated_string(input_json_params, nonce)
    data_objects = input_json_params['outData']
    data_objects.sort(key = lambda x:x['index'])
    hash_string_2 = self.calculate_datahash(data_objects)
    concat_string =  hash_string_1+ hash_string_2
    concat_hash = bytes(concat_string, 'UTF-8')
    final_hash = crypto.compute_message_hash(concat_hash)

    try:
        _verifying_key = crypto.SIG_PublicKey(verification_key)
    except Exception as error:
        logger.info("Error in verification key : %s", error)
        return SignatureStatus.INVALID_VERIFICATION_KEY

    decoded_signature = crypto.base64_to_byte_array(signature)
    sig_result =_verifying_key.VerifySignature(final_hash, decoded_signature)

    if sig_result == 1:
        return SignatureStatus.PASSED
    elif sig_result == 0:
        return SignatureStatus.FAILED
    else:
        return SignatureStatus.INVALID_SIGNATURE_FORMAT
