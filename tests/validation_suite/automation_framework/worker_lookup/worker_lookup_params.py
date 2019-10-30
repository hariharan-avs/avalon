import json
import logging

logger = logging.getLogger(__name__)

class WorkerLookUp():
    def __init__(self):
        self.id_obj = {"jsonrpc": "2.0", "method": "WorkerLookUp", "id": 1}
        self.params_obj = {}

    def add_json_values(self, input_json, tamper):

        # input_json_temp = json.loads(input_json)
        input_json_temp = input_json

        input_params_list = input_json_temp["params"].keys()

        if "workOrderId" in input_params_list :
            if input_json_temp["params"]["workerType"] != "" :
                self.set_worker_type(input_json_temp["params"]["workerType"])
            else :
                self.set_worker_type(1)

    def set_worker_type(self, worker_type):
        self.params_obj["workerType"] = worker_type

    def get_params(self):
        return self.params_obj.copy()

    def to_string(self):
        json_rpc_request = self.id_obj
        json_rpc_request["params"] = self.get_params()

        return json.dumps(json_rpc_request, indent=4)
