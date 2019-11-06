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

def tamper_object(input_obj, tamper):

    tamper_items_list = tamper["params"].items()

    for item in tamper_items_list :
        logger.info("------ Tamper item : %s , %s------\n", item, type(item))
        for key, value in item :
            if key not in input_obj.keys() :
                input_obj[key] = value

    return input_obj



#         logger.info("------ Type of tamper item : %s ------\n", type(item))
#         while type(item) == 'Dict' :
#             return_item = add_recursive_item(item)
#             if return_item != None :
#                 items = return_item
#     return input_obj
#
# def add_recursive_item(item) :
#     for key, value in item :
#         if key in input_obj.keys() :
#             input_value = input_obj[key]
#                 return input_value
#         else :
#             input_obj[key] = value
#             return None
