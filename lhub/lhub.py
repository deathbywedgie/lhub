import json
import re
from copy import deepcopy

from lhub.api import LogicHubAPI
from lhub.log import Logger


class LogicHub:
    log: Logger = None
    verify_ssl = True

    def __init__(self, hostname, api_key=None, username=None, password=None, verify_ssl=True, cache_seconds=None, **kwargs):
        # If the LogicHubAPI class object has not been given a logger by the time this class is instantiated, set one for it
        LogicHubAPI.log = LogicHubAPI.log or self.log or Logger()

        # If this class has not been given a logger by the time it is instantiated, set it to match the LogicHubAPI class's logger
        self.log = self.log or LogicHubAPI.log

        LogicHubAPI.verify_ssl = self.verify_ssl

        self.kwargs = kwargs
        self.api = LogicHubAPI(hostname=hostname, api_key=api_key, username=username, password=password, verify_ssl=verify_ssl, cache_seconds=cache_seconds, **kwargs)

    @property
    def case_prefix(self):
        return self.api.case_prefix

    def __me(self):
        return self.api.me()

    def verify_api_auth(self):
        response = self.__me()
        return response

    def _reformat_cmd_results(self, response_dict, drop_hidden_columns=True):
        full_result = response_dict.copy()

        result_raw = full_result["result"]
        warnings = full_result["result"].get("warnings")
        result_with_schema = result_raw["rows"]["data"]

        # execution_ids = [x["id"] for x in result_with_schema]

        if drop_hidden_columns:
            result_output = [{k: v for k, v in _result['fields'].items() if k not in ["lhub_id", "lhub_page_num"]} for _result in result_with_schema]
        else:
            result_output = [{k: v for k, v in _result['fields'].items()} for _result in result_with_schema]

        for _warning in warnings:
            self.log.debug(f"WARNING RETURNED: {_warning}")

        return result_output, warnings

    def execute_command(self, command_name, input_dict, reformat=True, result_limit=25):
        response = self.api.execute_command({"command": command_name, "parameterValues": input_dict, "limit": result_limit})
        if not reformat:
            return response

        response, _ = self._reformat_cmd_results(response)
        return response

    def action_list_custom_lists(self, search_text: str = None, filters: list = None, limit: int = None, offset: int = None):
        results = self.api.get_custom_lists(search_text=search_text, filters=filters, limit=limit, offset=offset, verify_results=False)
        warnings = []
        try:
            results = results["result"]["data"]
        except KeyError:
            warnings.append("API response does not match the expected schema for listing custom lists")
        return results, warnings

    def action_get_streams(self, search_text: str = None, filters: list = None, limit: int = 25, offset: int = 0):
        response = self.api.get_streams(search_text=search_text, filters=filters, limit=limit, offset=offset)
        return response["result"]["data"]["data"]

    def action_get_integrations(self, name_filter: str = None, filter_type="contains"):
        filter_type = filter_type.lower()
        assert filter_type in ["equals", "contains"], f"Invalid filter type \"{filter_type}\""
        assert isinstance(name_filter, str), "name_filter must be a string and cannot be None"

        _response = self.api.get_integrations()

        # _query = _response.pop("query")
        _result = _response.pop("result")
        categories = _result["categories"]
        results = _result["objects"]

        if name_filter:
            if filter_type == "contains":
                results = [result for result in results if name_filter.lower() in result["resource"]["name"].lower()]
            else:
                new_result = {}
                for result in results:
                    if result["resource"]["name"].lower() == name_filter.lower():
                        new_result = result
                        break
                results = new_result
        return results, categories

    # ToDo This finally works as of m91. Add an action for it.
    def action_get_stream_by_id(self, stream_id: int):
        result = self.api.get_stream_by_id(stream_id)
        return result["result"]

    def action_get_batches_by_stream_id(self, stream_id: int, limit=None, statuses=None, exclude_empty_results=False):
        """
        Get all batches for a given stream

        :param stream_id: ID of the stream
        :param limit: Optional: set a batch limit (default it unlimited, despite the fact that the API's actual default is 25)
        :param statuses: Optional: List of statuses to include in the results
        :param exclude_empty_results: Optional: exclude successful batches which did not output any data
        :return: Batch results in the form of a list of dicts
        """
        result = self.api.get_batches_by_stream_id(stream_id, limit=limit or -1, statuses=statuses, exclude_empty_results=exclude_empty_results)
        _ = self._result_dict_has_schema(result, "result", "data", raise_errors=True, action_description="get batches by stream ID")
        return result["result"]["data"]

    def action_get_batch_results_by_id(self, batch_id: int, limit=1000, keep_additional_info=False):
        result = self.api.get_batch_results_by_id(batch_id=batch_id, limit=limit)
        _ = self._result_dict_has_schema(result, "result", "data", raise_errors=True, action_description="fetch batch results")
        result = result["result"]["data"]
        if not keep_additional_info:
            result = [r["columns"] for r in result]
        return result

    def action_get_version(self):
        return self.api.version_info

    def action_get_workflow_by_id(self, workflow_id):
        if isinstance(workflow_id, str):
            workflow_id = re.findall(r"(\d+)", workflow_id)
            if not workflow_id:
                raise ValueError("Invalid Workflow ID: no numeric value found")
            workflow_id = workflow_id[0]
        workflow_id = int(workflow_id)
        result = self.api.get_workflow_by_id(workflow_id=workflow_id)
        _ = self._result_dict_has_schema(result, "result", raise_errors=True, action_description="fetch workflow by ID")
        return result["result"]

    @staticmethod
    def _result_dict_has_schema(result_dict, *fields, raise_errors=False, action_description=None, accept_null=False):
        _dict = result_dict
        for field in fields:
            if field not in _dict.keys() or _dict.get(field) is None and not accept_null:
                if raise_errors is True:
                    action_description = f" [{action_description}]" if action_description else ''
                    err_msg = f"Response{action_description} did not match the expected JSON schema. Missing expected key: {field}"
                    raise ValueError(err_msg)
                return False
            _dict = _dict[field]
        return True

    def action_list_baselines(self):
        result = self.api.list_baselines()
        _ = self._result_dict_has_schema(result, "result", "data", "data", raise_errors=True, action_description="list baselines")
        result = result["result"]["data"]
        baselines = result['data']
        stream_ids = [int(b['id']['id']) for b in baselines]
        stream_state_response = self.api.get_stream_states(stream_ids=stream_ids)
        _ = self._result_dict_has_schema(stream_state_response, "result", "streams", raise_errors=True, action_description="fetch stream states")
        state_map = {_stream['streamId']: _stream['status'] for _stream in stream_state_response['result']['streams']}
        for n in range(len(baselines)):
            b = baselines[n]
            _id = int(b['id']['id'])
            baselines[n]['baseline_config_status'] = state_map.get(f"stream-{b['id']['id']}")
        return result

    def action_list_fields(self, map_mode=None):
        assert not map_mode or map_mode in ['id', 'name'], f'Invalid output format: {map_mode}'
        result = self.api.fields
        _ = self._result_dict_has_schema(result, "result", "data", raise_errors=True, action_description="list fields")
        output = result["result"]["data"]
        if map_mode == "id":
            output = {f['id']: {k: v for k, v in f.items() if k != 'id'} for f in output}
        elif map_mode == "name":
            output = {f['fieldName']: {k: v for k, v in f.items() if k != 'fieldName'} for f in output}
        return output

    def action_list_modules(self, local_only=False):
        result = self.api.list_modules()
        _ = self._result_dict_has_schema(result, "result", "objects", action_description="list modules", raise_errors=True)
        other_details = result["result"]
        modules = other_details.pop('objects')

        # If local_only is set to True, only return the modules with a contentRepoStatus of "Local"
        if local_only is True:
            modules = [x for x in modules if x['metadata']['contentRepoStatus'].lower() == 'local']

        return modules, other_details

    def action_list_connections(self, add_status=False):
        result = self.api.list_connections()
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list connections", raise_errors=True)
        result = result["result"]["data"]
        if not add_status:
            return result

        connections = result["data"]
        connection_ids = [connection["id"]["id"] for connection in connections]
        status_results = self.api.get_connection_status(connection_ids)
        statuses = {status["connectionEntityId"].replace("connection-", ''): status["status"] for status in status_results['result']}
        for n in range(len(connections)):
            connection = connections[n]
            connection_id = str(connection["id"]["id"])
            connection["status"] = statuses.get(connection_id)
            if not connection["status"]:
                raise ValueError(f"Connection ID {connection_id} missing from status list")
        return result

    def action_list_workflows(self):
        result = self.api.get_workflows()
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list workflows", raise_errors=True)
        return result["result"]["data"]

    def action_reprocess_batch(self, batch_id):
        return self.api.reprocess_batch(batch_id)

    def action_list_notebooks(self):
        result = self.api.notebooks_list()
        _ = self._result_dict_has_schema(result, "result", "data", "data", action_description="list notebooks", raise_errors=True)
        return result["result"]["data"]

    def action_get_notebooks_attached_to_case(self, case_id):
        response = self.api.case_list_attached_notebooks(case_id)
        _ = self._result_dict_has_schema(response, "result", action_description="get notebooks from case", raise_errors=True)
        return response.get('result', [])

    def action_attach_notebooks_from_case(self, case_id, notebook_ids):
        current_notebooks = self.api.case_list_attached_notebooks(case_id, results_only=True)
        current_notebooks = [notebook['id'] for notebook in current_notebooks]
        new_notebooks = self.api._format_notebook_ids(notebook_ids)
        updated_notebooks = current_notebooks + [x for x in new_notebooks if x not in current_notebooks]
        if current_notebooks == updated_notebooks:
            return {"result": "no changes made"}
        return self.api.case_overwrite_attached_notebooks(case_id, updated_notebooks)

    def action_detach_notebooks_from_case(self, case_id, notebook_ids):
        current_notebooks = self.api.case_list_attached_notebooks(case_id, results_only=True)
        if not current_notebooks:
            return {"result": "no changes made"}
        # Reformat to match
        current_notebooks = self.api._format_notebook_ids(current_notebooks)
        new_notebooks = self.api._format_notebook_ids(notebook_ids)
        updated_notebooks = [notebook for notebook in current_notebooks if notebook['id'] not in [x['id'] for x in new_notebooks]]
        if current_notebooks == updated_notebooks:
            return {"result": "no changes made"}
        return self.api.case_overwrite_attached_notebooks(case_id, updated_notebooks)

    def action_remove_all_notebooks_from_case(self, case_id):
        current_notebooks = self.api.case_list_attached_notebooks(case_id, results_only=True)
        if not current_notebooks:
            return {"result": "no changes made"}
        return self.api.case_overwrite_attached_notebooks(case_id, [])

    def action_list_user_groups(self, hide_inactive=False):
        result = self.api.user_groups(hide_inactive=hide_inactive)
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list user groups", raise_errors=True)
        return result["result"]

    def action_list_users(self, hide_inactive=False):
        result = self.api.users(hide_inactive=hide_inactive)
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list users", raise_errors=True)
        return result["result"]

    @staticmethod
    def __enrich_alert_data(alert: dict, included_standard_fields=None, included_additional_fields=None):
        # Verify and sanitize inputs
        if not alert:
            return {}
        alert = deepcopy(alert)
        if not isinstance(included_standard_fields, list):
            included_standard_fields = [included_standard_fields] if included_standard_fields else []
        included_standard_fields = [f.strip() for f in included_standard_fields if f and f.strip()]
        if not isinstance(included_additional_fields, list):
            included_additional_fields = [included_additional_fields] if included_additional_fields else []
        included_additional_fields = [f.strip() for f in included_additional_fields if f and f.strip()]

        if not included_standard_fields and not included_additional_fields:
            return alert

        additional_fields = alert.pop('additionalFields', [])
        additional_fields = [f for f in additional_fields if not included_additional_fields or f.get('displayName') in included_additional_fields]

        mapped_fields = alert.pop('mappedAlertFieldValues', [])
        mapped_fields = [f for f in mapped_fields if not included_standard_fields or f.get('displayName') in included_standard_fields]

        new_alert = {'id': alert.pop('id')}
        new_alert.update({k: v for k, v in alert.items() if not included_standard_fields or k in included_standard_fields})
        new_alert.update({
            'additionalFields': additional_fields,
            'mappedAlertFieldValues': mapped_fields,
        })
        return new_alert

    @staticmethod
    def _reformat_alert_simple(alert: dict):
        if not alert:
            return {}
        alert = deepcopy(alert)
        # From this: {"displayName": "batch_start_millis", "value": "1632146400000"}
        # To this: {"batch_start_millis": "1632146400000"}
        alert['additionalFields'] = {x['displayName']: x['value'] for x in alert.get('additionalFields', {}) if x.get('displayName')}

        # From this: {"caseFieldId": "field-17", "displayName": "Alert Context", "fieldType": "Text", "value": "mdr_test"}
        # To this: {"Alert Context": "mdr_test"}
        for k in alert.get('mappedAlertFieldValues', {}):
            if k.get('fieldType') == 'JSON':
                try:
                    k['value'] = json.loads(k['value'])
                except (ValueError, TypeError, json.decoder.JSONDecodeError):
                    pass
        alert['mappedAlertFieldValues'] = {x['displayName']: x['value'] for x in alert.get('mappedAlertFieldValues', {}) if x.get('displayName')}
        return alert

    def action_fetch_alert(self, alert_id, simple_format=False, included_standard_fields=None, included_additional_fields=None):
        result = self.api.alert_fetch(alert_id)
        _ = self._result_dict_has_schema(result, "result", action_description="list users", raise_errors=True)

        # Reformat alert and enrich as needed
        output = self.__enrich_alert_data(
            result['result'],
            included_standard_fields=included_standard_fields,
            included_additional_fields=included_additional_fields
        )

        # Simplify mapped and additional field output
        if simple_format:
            output = self._reformat_alert_simple(output)
            # field_map = self.action_list_fields(map_mode="name")
            # output['additionalFields'] = {}
        return output

    def action_alerts_search_advanced(self, query: str = None, limit: int = None, fetch_details=None, included_standard_fields=None, included_additional_fields=None):
        simple_format = False
        if fetch_details:
            if fetch_details not in ['standard', 'simple']:
                raise ValueError(f'Invalid input for fetch_details: {fetch_details}')
            elif fetch_details == 'simple':
                simple_format = True
        query = query.strip() if query and query.strip() else ""
        result = self.api.alerts_search_advanced(query=query, limit=limit)
        _ = self._result_dict_has_schema(result, "result", action_description="search alerts", raise_errors=True)
        output = result['result']
        if fetch_details:
            alerts = [x['id'] for x in output['data']]
            return [
                self.action_fetch_alert(alert, simple_format=simple_format, included_standard_fields=included_standard_fields, included_additional_fields=included_additional_fields)
                for alert in alerts
            ]
        return output

    def action_get_case_prefix(self):
        return self.case_prefix

    def action_pause_stream(self, stream_id):
        result = self.api.stream_pause(stream_id=stream_id)
        _ = self._result_dict_has_schema(result, "result", action_description="pause stream", raise_errors=True, accept_null=True)
        return result

    def action_resume_stream(self, stream_id):
        result = self.api.stream_resume(stream_id=stream_id)
        _ = self._result_dict_has_schema(result, "result", action_description="resume stream", raise_errors=True, accept_null=True)
        return result
