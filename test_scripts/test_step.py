import pytest
import subprocess
import time
from pytest_jsonreport.plugin import JSONReport

#plugin = JSONReport()
#plugin.save_report('/tcf/reports/report.json')

def exc_test(cmd):
    result = subprocess.run([
      '/bin/bash',
      '-c',
      cmd
    ], stdout=subprocess.PIPE)
    returncode = result.returncode
    stdout = result.stdout
    stderr = result.stderr

    return result

def test_wo_success(json_metadata):
    r = exc_test('python test_wo_success.py --input_dir ./wo_success/ --connect_uri "http://localhost:1947" wo_success')

    json_metadata['script'] = "test_wo_success.py"
    json_metadata['input_dir']= "wo_success"
    json_metadata['description']= "Test to submit workorder request and validate the response"
    json_metadata['additional_info']= "Expected result: 0 – Success"

    assert r.returncode == 0

def test_wo_req_inv(json_metadata):
    r = exc_test('python test_wo_req_inv.py --input_dir ./wo_req_inv/ --connect_uri "http://localhost:1947" wo_req_inv')
    json_metadata['script'] = "test_wo_req_inv.py"
    json_metadata['input_dir']= "wo_req_inv"
    json_metadata['description']= "Received Work Order request and submit invalid work order request payload to validate the returned error"
    json_metadata['additional_info']= "Expected result: 10 - Refer json-RPC Error Codes for more details"

    assert r.returncode == 0

def test_wo_pending(json_metadata):
    r = exc_test('python test_wo_pending.py --input_dir ./wo_pending/ --connect_uri "http://localhost:1947" wo_pending')
    json_metadata['script'] = "test_wo_pending.py"
    json_metadata['input_dir']= "wo_pending"
    json_metadata['description']= "Work Order status pending – scheduled to be executed, but not started yet"
    json_metadata['additional_info']= "Expected result: Work order state error response with codes 5"

    assert r.returncode == 0

def test_wo_submit_key_already_exist(json_metadata):
    r = exc_test('python test_wo_submit_key_already_exist.py --input_dir ./wo_submit_key_already_exist/ --connect_uri "http://localhost:1947" wo_submit_key_already_exist')
    json_metadata['script'] = "test_wo_submit_key_already_exist.py"
    json_metadata['input_dir']= "wo_submit_key_already_exist"
    json_metadata['description']= " WorkOrderSubmit-Work Order request is received and return the response with error code 8 and message key already exist"
    json_metadata['additional_info']= "Expected result: 8 – key already exists"

    assert r.returncode == 1

def test_wo_inv_param(json_metadata):
    r = exc_test('python test_wo_inv_param.py --input_dir ./wo_inv_param/ --connect_uri "http://localhost:1947" wo_inv_param')
    json_metadata['script'] = "test_wo_inv_param.py"
    json_metadata['input_dir']= "wo_inv_param"
    json_metadata['description']= "Submit work order with invalid parameter value and validate the response"
    json_metadata['additional_info']= "Expected result: 2 – invalid parameter format or value"

    assert r.returncode == 1

def test_wo_not_alw_param(json_metadata):
    r = exc_test('python test_wo_not_alw_param.py --input_dir ./wo_not_alw_param/ --connect_uri "http://localhost:1947" wo_not_alw_param')
    json_metadata['script'] = "test_wo_not_alw_param.py"
    json_metadata['input_dir']= "wo_not_alw_param"
    json_metadata['description']= "Submit work order not allowed to access the parameters and validate the response"
    json_metadata['additional_info']= "Expected result: 3 – access denied"

    assert r.returncode == 1

def test_wo_req_unk(json_metadata):
    r = exc_test('python test_wo_req_unk.py --input_dir ./wo_req_sig_wrg/ --connect_uri "http://localhost:1947" wo_req_sig_wrg')
    json_metadata['script'] = "test_wo_req_unk.py"
    json_metadata['input_dir']= "wo_req_unk"
    json_metadata['description']= "Work Order Request Payload submitted with unknown parameters in input"
    json_metadata['additional_info']= "Expected result: 0 - successfull processing when unknown parameters are provided in addition to valid parameters"

    assert r.returncode == 0
    

def test_wo_res_pay(json_metadata):
    r = exc_test('python test_wo_res_pay.py --input_dir ./wo_res_pay/ --connect_uri "http://localhost:1947" wo_res_pay')
    json_metadata['script'] = "test_wo_res_pay.py"
    json_metadata['input_dir']= "wo_res_pay"
    json_metadata['description']= "Test to submit workorder request and validate the response"
    json_metadata['additional_info']= "Expected result: If a submitted Work Order is completed, 10-As per JSON RPC specification"

    assert r.returncode == 0

def test_wo_get_res(json_metadata):
    r = exc_test('python test_wo_get_res.py --input_dir ./wo_get_res/ --connect_uri "http://localhost:1947" wo_get_res')
    json_metadata['script'] = "test_wo_get_res.py"
    json_metadata['input_dir']= "wo_get_res"
    json_metadata['description']= "Work Order Pull Request Payload with Pull the Worker Service periodically"
    json_metadata['additional_info']= "Expected result-Method: WorkOrderGetResult-Pull the Worker Service periodically until the Work Order is completed successfully"

    assert r.returncode == 0

def test_wo_ind_out(json_metadata):
    r = exc_test('python test_wo_ind_out.py --input_dir ./wo_ind_out/ --connect_uri "http://localhost:1947" wo_ind_out')
    json_metadata['script'] = "test_wo_ind_out.py"
    json_metadata['input_dir']= "wo_ind_out"
    json_metadata['description']= "Work Order Data Formats for inData and outData elements within work order request and response"
    json_metadata['additional_info']= "Expected result: inData in the work order request and outData in the response"

    assert r.returncode == 1

def test_wo_req_sig(json_metadata):
    r = exc_test('python test_wo_req_sig.py --input_dir ./wo_req_sig/ --connect_uri "http://localhost:1947" wo_req_sig')
    json_metadata['script'] = "test_wo_req_sig.py"
    json_metadata['input_dir']= "wo_req_sig"
    json_metadata['description']= "Work Order request signing"
    json_metadata['additional_info']= "Expected result: Validate work order request with signingAlgorithm, Work Order request hash and signature is formatted as a BASE64 string. Result string is placed in requesterSignature of the Work Order request payload"

    assert r.returncode == 1

def test_wo_res_sign(json_metadata):
    r = exc_test('python test_wo_res_sign.py --input_dir ./wo_res_sign/ --connect_uri "http://localhost:1947" wo_res_sign')
    json_metadata['script'] = "test_wo_res_sign.py"
    json_metadata['input_dir']= "wo_res_sign"
    json_metadata['description']= "Work Order response signing"
    json_metadata['additional_info']= "Expected result: Varification is same steps just resulting string is placed in workerSignature of the Work Order response payload"

    assert r.returncode == 1

def test_worker_lookup(json_metadata):
    r = exc_test('python test_worker_lookup.py --input_dir ./worker_lookup/ --connect_uri "http://localhost:1947" worker_lookup')
    json_metadata['script'] = "test_worker_lookup.py"
    json_metadata['input_dir']= "worker_lookup"
    json_metadata['description']= "Initiates a Worker lookup in the registry"
    json_metadata['additional_info']= "Expected result: Worker lookup JSON response payload with id and result as WorkerLookUp and result"

    assert r.returncode == 0

def test_worker_retrieve(json_metadata):
    r = exc_test('python test_worker_retrieve.py --input_dir ./worker_retrieve/ --connect_uri "http://localhost:1947" worker_retrieve')
    json_metadata['script'] = "test_worker_retrieve.py"
    json_metadata['input_dir']= "worker_retrieve"
    json_metadata['description']= "Worker Retrieve JSON Payload"
    json_metadata['additional_info']= "Expected result: Worker Retrieve Response JSON Payload"

    assert r.returncode == 0

def test_wo_sign_req_result_requesterSign(json_metadata):
    r = exc_test('python test_wo_sign_req_result_requesterSign.py --input_dir ./wo_sign_req_result_requesterSign/ --connect_uri "http://localhost:1947" wo_sign_req_result_requesterSign')
    json_metadata['script'] = "test_wo_sign_req_result_requesterSign.py"
    json_metadata['input_dir']= "wo_sign_req_result_requesterSign"
    json_metadata['description']= "Work order request payload with signatures and data items are formatted with proper parameter (payloadFormat), corresponding response"
    json_metadata['additional_info']= "Expected result: Work order payload formats with JSON-RPC as a result"

    assert r.returncode == 0

def test_wo_sig_res_param_signingAlg(json_metadata):
    r = exc_test('python test_wo_sig_res_param_signingAlg.py --input_dir ./wo_sig_res_param_signingAlg/ --connect_uri "http://localhost:1947" wo_sig_req_param_signingAlg')
    json_metadata['script'] = "test_wo_sig_res_param_signingAlg.py"
    json_metadata['input_dir']= "wo_sig_res_param_signingAlg"
    json_metadata['description']= "Work Order request with signing mechanism in Worker's parameter signingAlgorithm"
    json_metadata['additional_info']= "Expected result: Received Worker request retrieve parameter signingAlgorithm and start the signature generation process"

    assert r.returncode == 0

def test_wo_sig_res_hash_worker_priv_sign_key(json_metadata):
    r = exc_test('python test_wo_sig_res_hash_worker_priv_sign_key.py --input_dir ./wo_sig_res_hash_worker_priv_sign_key/ --connect_uri "http://localhost:1947" wo_sig_res_hash_worker_priv_sign_key')
    json_metadata['script'] = "test_wo_sig_res_hash_worker_priv_sign_key.py"
    json_metadata['input_dir']= "wo_sig_res_hash_worker_priv_sign_key"
    json_metadata['description']= "Work Order response hash calculation with data hash data encryptedDataEncryptionKey inData and outData"
    json_metadata['additional_info']= "Expected result: Final hash calculated successfully"

    assert r.returncode == 1

def test_wo_sign_res_result_workerSignature(json_metadata):
    r = exc_test('python test_wo_sign_res_result_workerSignature.py --input_dir ./wo_sign_res_result_workerSignature/ --connect_uri "http://localhost:1947" wo_sign_res_result_workerSignature')
    json_metadata['script'] = "test_wo_sign_res_result_workerSignature"
    json_metadata['input_dir']= "wo_sign_res_result_workerSignature"
    json_metadata['description']= "Work Order request payload with worker dont pass encryption key and get response"
    json_metadata['additional_info']= "Expected result: Worker encryption key should process request successfully"

    assert r.returncode == 0

def test_wo_param_hash_algo_define(json_metadata):
    r = exc_test('python test_wo_param_hash_algo_define.py --input_dir ./wo_param_hash_algo_define/ --connect_uri "http://localhost:1947" wo_param_hash_algo_define')
    json_metadata['script'] = "test_wo_param_hash_algo_define.py"
    json_metadata['input_dir']= "wo_param_hash_algo_define"
    json_metadata['description']= "Submit work order request wrong algorithm and validate the response"
    json_metadata['additional_info']= "Expected result: Wrong hash algorithm"

    assert r.returncode == 0

def test_wo_req_worker_encryp_key(json_metadata):
    r = exc_test('python test_wo_req_worker_encryp_key.py --input_dir ./wo_req_worker_encryp_key/ --connect_uri "http://localhost:1947" wo_req_worker_encryp_key')
    json_metadata['script'] = "test_wo_req_worker_encryp_key.py"
    json_metadata['input_dir']= "wo_req_worker_encryp_key"
    json_metadata['description']= "Fail to retrieve Registry lookup results initiated by registryLookUp call"
    json_metadata['additional_info']= "Expected result: 5 - no more look up results"

    assert r.returncode == 0

def test_wo_req_data_encryp_Alg(json_metadata):
    r = exc_test('python test_wo_req_data_encryp_Alg.py --input_dir ./wo_req_data_encryp_Alg/ --connect_uri "http://localhost:1947" wo_req_data_encryp_Alg')
    json_metadata['script'] = "test_wo_req_data_encryp_Alg.py"
    json_metadata['input_dir']= "wo_req_data_encryp_Alg"
    json_metadata['description']= "Worker Lookup Response JSON Payload"
    json_metadata['additional_info']= "Expected result: Payload is sent back to a Requester in response to the worker lookup request"

    assert r.returncode == 0

def test_worker_register(json_metadata):
    r = exc_test('python test_worker_register.py --input_dir ./worker_register/ --connect_uri "http://localhost:1947" worker_register')
    json_metadata['script'] = "test_worker_register.py"
    json_metadata['input_dir']= "worker_register"
    json_metadata['description']= "Successfully register a worker"
    json_metadata['additional_info']= "Expected result: 0 – Success"

    assert r.returncode == 0

def test_worker_reg_unk(json_metadata):
    r = exc_test('python test_worker_reg_unk.py --input_dir ./worker_reg_unk/ --connect_uri "http://localhost:1947" worker_reg_unk')
    json_metadata['script'] = "test_worker_reg_unk.py"
    json_metadata['input_dir']= "worker_reg_unk"
    json_metadata['description']= "Submit worker registry with uri error in request and validate the response"
    json_metadata['additional_info']= "Expected result:  1 – unknown error"

    assert r.returncode == 0

def test_worker_reg_inv_param(json_metadata):
    r = exc_test('python test_worker_reg_inv_param.py --input_dir ./worker_reg_inv_param/ --connect_uri "http://localhost:1947" worker_reg_inv_param')
    json_metadata['script'] = "test_worker_reg_inv_param.py"
    json_metadata['input_dir']= "worker_reg_inv_param"
    json_metadata['description']= "Submit worker registry with existing worker id value and validate the response"
    json_metadata['additional_info']= "Expected result: 2 – invalid parameter value"

    assert r.returncode == 0

def test_worker_upd_success(json_metadata):
    r = exc_test('python test_worker_upd_success.py --input_dir ./worker_upd_success/ --connect_uri "http://localhost:1947" worker_upd_success')
    json_metadata['script'] = "test_worker_upd_success.py"
    json_metadata['input_dir']= "worker_upd_success"
    json_metadata['description']= "Submit updated worker with success and validate the response"
    json_metadata['additional_info']= "Expected result: 0 – Success"

    assert r.returncode == 0

def test_worker_unk_param(json_metadata):
    r = exc_test('python test_worker_unk_param.py --input_dir ./worker_unk_param/ --connect_uri "http://localhost:1947" worker_unk_param')
    json_metadata['script'] = "test_worker_unk_param.py"
    json_metadata['input_dir']= "worker_unk_param"
    json_metadata['description']= "Submit updated worker with uri error in request and validate the response"
    json_metadata['additional_info']= "Expected result: 1 – unknown error"

    assert r.returncode == 0

def test_worker_inv_param(json_metadata):
    r = exc_test('python test_worker_inv_param.py --input_dir ./worker_inv_param/ --connect_uri "http://localhost:1947" worker_inv_param')
    json_metadata['script'] = "test_worker_inv_param.py"
    json_metadata['input_dir']= "worker_inv_param"
    json_metadata['description']= "Submit updated worker with unknown error and validate the response"
    json_metadata['additional_info']= "Expected result: 2 – invalid parameter format or value"

    assert r.returncode == 0

def test_worker_status_success(json_metadata):
    r = exc_test('python test_worker_status_success.py --input_dir ./worker_status_success/ --connect_uri "http://localhost:1947" worker_status_success')
    json_metadata['script'] = "test_worker_status_success.py"
    json_metadata['input_dir']= "worker_status_success"
    json_metadata['description']= "Sets a Worker’s status successfully"
    json_metadata['additional_info']= "Expected result: 0 – Success"

    assert r.returncode == 0

def test_worker_status_unk(json_metadata):
    r = exc_test('python test_worker_status_unk.py --input_dir ./worker_status_unk/ --connect_uri "http://localhost:1947" worker_status_unk')
    json_metadata['script'] = "test_worker_status_unk.py"
    json_metadata['input_dir']= "worker_status_unk"
    json_metadata['description']= "Set a Worker's status with unknown error and validate the response"
    json_metadata['additional_info']= "Expected result: 1 – unknown error"

    assert r.returncode == 0

def test_worker_status_inv_param(json_metadata):
    r = exc_test('python test_worker_status_inv_param.py --input_dir ./worker_status_inv_param/ --connect_uri "http://localhost:1947" worker_status_inv_param')
    json_metadata['script'] = "test_worker_status_inv_param.py"
    json_metadata['input_dir']= "worker_status_inv_param"
    json_metadata['description']= "Set a Worker's status with invalid parameter value and validate the response"
    json_metadata['additional_info']= "Expected result: 2 – invalid parameter format or value"

    assert r.returncode == 0
