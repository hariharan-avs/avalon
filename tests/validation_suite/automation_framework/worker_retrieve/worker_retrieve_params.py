import json
import logging

logger = logging.getLogger(__name__)

class WorkerRetrieve():
    def __init__(self):
        self.id_obj = {"jsonrpc": "2.0", "method": "WorkerRetrieve", "id": 2}
        self.params_obj = {}

    def add_json_values(self, input_json, tamper):

        # input_json_temp = json.loads(input_json)
        input_json_temp = input_json

        input_params_list = input_json_temp["params"].keys()

        if "workerId" in input_params_list :
            if input_json_temp["params"]["workerId"] != "" :
                self.set_work_order_id(input_json_temp["params"]["workerId"])
            else :
                work_order_id = hex(random.randint(1, 2**64 -1))
                self.set_work_order_id(work_order_id)

    def set_worker_id(self, worker_id):
        self.params_obj["workerId"] = worker_id

    def get_params(self):
        return self.params_obj.copy()

    def to_string(self):
        json_rpc_request = self.id_obj
        json_rpc_request["params"] = self.get_params()

        return json.dumps(json_rpc_request, indent=4)