import json
import logging

import automation_framework.worker.worker_params as worker

logger = logging.getLogger(__name__)

class WorkerSetStatus():
    def __init__(self):
        self.id_obj = {"jsonrpc": "2.0", "method": "WorkerSetStatus", "id": 12}
        self.params_obj = {}

    def add_json_values(self, input_json, worker_obj):

        input_json_temp = input_json

        if "workerId" in input_json_temp["params"].keys() :
            if input_json_temp["params"]["workerId"] != "" :
                self.set_worker_id(input_json_temp["params"]["workerId"])
            else :
                worker_id = worker_obj.worker_id
                self.set_worker_id(worker_id)

        if "id" in input_json_temp.keys() :
            self.set_request_id(input_json_temp["id"])

        if "status" in input_json_temp["params"].keys() :
            if input_json_temp["params"]["status"] != "" :
                self.set_status(input_json_temp["params"]["status"])
            else :
                self.set_status(1)

    def set_worker_id(self, worker_id):
        self.params_obj["workerId"] = worker_id

    def set_request_id(self, request_id):
        self.id_obj["id"] = request_id

    def set_status(self, status):
        self.params_obj["status"] = status

    def get_params(self):
        return self.params_obj.copy()

    def to_string(self):
        json_rpc_request = self.id_obj
        json_rpc_request["params"] = self.get_params()

        return json.dumps(json_rpc_request, indent=4)