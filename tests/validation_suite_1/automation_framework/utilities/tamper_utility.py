import pytest
import json

def tamper_request(input_json_str1, tamper):

    after_sign_keys = []
    input_json_temp = json.loads(input_json_str1)
    if "after_sign" in tamper["params"].keys():
        after_sign_keys = tamper["params"]["after_sign"].keys()

    for tamper_key in after_sign_keys:
        input_json_temp["params"][tamper_key] = tamper["params"]["after_sign"][tamper_key]

    input_json_str1 = json.dumps(input_json_temp)

    return input_json_str1
