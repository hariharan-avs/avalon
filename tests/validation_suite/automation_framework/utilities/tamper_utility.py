import pytest
import json

def tamper_request(input_json, tamper_instance, tamper):
    '''Function to tamper the input request at required instances.
       Valid instances used in test framework are :
       force, add, remove.
       force : used by WorkOrderSubmit() class primarily to force null values.
       add : can be used to add a parameter and value not in input json,
             also can be used to replace a value for parameter in input json
       remove : deletes the parameter from input json

       The function can be used for other instances also provided the instances
       are used in test framework and also value of tamper defined in test case

       A blank tamper dictionary is required for all test cases, in cases where
       tamper functionality is not required. Example : tamper{"params":{}}'''


    before_sign_keys = []
    after_sign_keys = []
    input_json_temp = json.loads(input_json)

    if tamper_instance in tamper["params"].keys() :
        tamper_instance_keys = tamper["params"][tamper_instance].keys()

        for tamper_key in tamper_instance_keys :
            for action_key in (
                    tamper["params"][tamper_instance][tamper_key].keys()) :
                if action_key == "add" :
                    input_json_temp["params"][tamper_key] = (
                    tamper["params"][tamper_instance][tamper_key]["add"])
                elif action_key == "remove" :
                    del input_json_temp["params"][tamper_key]

    tampered_json = json.dumps(input_json_temp)

    return tampered_json
