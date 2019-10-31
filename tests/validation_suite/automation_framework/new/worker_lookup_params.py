import json
import logging

logger = logging.getLogger(__name__)

class WorkerLookUp():
    def __init__(self):
        self.id_obj = {"jsonrpc": "2.0", "method": "WorkerLookUp", "id": 1}
        self.params_obj = {}

    def add_json_values(self, input_json):

        # input_json_temp = json.loads(input_json)
        input_json_temp = input_json
        #
        # input_params_list = input_json_temp["params"].keys()

        if "workOrderId" in input_json_temp["params"].keys() :
            if input_json_temp["params"]["workerType"] != "" :
                self.set_worker_type(input_json_temp["params"]["workerType"])
            else :
                self.set_worker_type(1)

        if "id" in input_json_temp.keys() :
            self.set_request_id(input_json_temp["id"])

    def set_worker_type(self, worker_type):
        self.params_obj["workerType"] = worker_type

    def set_request_id(self, request_id):
        self.id_obj["id"] = request_id

    def get_params(self):
        return self.params_obj.copy()

    def to_string(self):
        json_rpc_request = self.id_obj
        json_rpc_request["params"] = self.get_params()

        return json.dumps(json_rpc_request, indent=4)
