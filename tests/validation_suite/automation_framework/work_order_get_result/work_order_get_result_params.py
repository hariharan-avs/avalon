import json
import logging

logger = logging.getLogger(__name__)

class WorkOrderGetResult():
    def __init__(self):
        self.id_obj = {"jsonrpc": "2.0", "method": "WorkOrderGetResult", "id": 4}
        self.params_obj = {}

    def add_json_values(self, input_json, tamper):

        # input_json_temp = json.loads(input_json)
        input_json_temp = input_json

        input_params_list = input_json_temp["params"].keys()

        if "workOrderId" in input_params_list :
            if input_json_temp["params"]["workOrderId"] != "" :
                self.set_work_order_id(input_json_temp["params"]["workOrderId"])
            else :
                work_order_id = hex(random.randint(1, 2**64 -1))
                self.set_work_order_id(work_order_id)

    def set_work_order_id(self, work_order_id):
        self.params_obj["workOrderId"] = work_order_id

    def set_request_id(self, request_id):
        self.id_obj["id"] = request_id

    def get_params(self):
        return self.params_obj.copy()

    def to_string(self):
        json_rpc_request = self.id_obj
        json_rpc_request["params"] = self.get_params()

        return json.dumps(json_rpc_request, indent=4)
