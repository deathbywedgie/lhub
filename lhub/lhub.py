import json
import re
from copy import deepcopy

from .api import LogicHubAPI
from .log import Logger
from .common.helpers import format_notebook_ids
from .common.time import epoch_time_to_str
from .exceptions.app import BaseAppError
from .exceptions.validation import InputValidationError, ResponseValidationError
from .exceptions.formatting import InvalidWorkflowIdFormat


class Actions:
    log = None

    def __init__(self, api: LogicHubAPI):
        self.__api = api

        # If this class has not been given a logger by the time it is instantiated, inherit the same one from LogicHubAPI
        self.log = self.log or self.__api.log

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

        additional_fields = alert.pop('additionalFields', {})
        if isinstance(additional_fields, list):
            additional_fields = [f for f in additional_fields if not included_additional_fields or f.get('displayName') in included_additional_fields]
        else:
            additional_fields = {k: v for k, v in additional_fields.items() if not included_additional_fields or k in included_additional_fields}

        mapped_fields = alert.pop('mappedAlertFieldValues', [])
        if isinstance(mapped_fields, list):
            mapped_fields = [f for f in mapped_fields if not included_standard_fields or f.get('displayName') in included_standard_fields]
        else:
            mapped_fields = {k: v for k, v in mapped_fields.items() if not included_standard_fields or k in included_standard_fields}

        new_alert = {'id': alert.pop('id')}
        new_alert.update({k: v for k, v in alert.items() if not included_standard_fields or k in included_standard_fields})
        new_alert.update({
            'additionalFields': additional_fields,
            'mappedAlertFieldValues': mapped_fields,
        })
        return new_alert

    @staticmethod
    def _result_dict_has_schema(result_dict, *fields, raise_errors=False, action_description=None, accept_null=False):
        _dict = result_dict
        for field in fields:
            if field not in _dict.keys() or _dict.get(field) is None and not accept_null:
                if raise_errors is True:
                    action_description = f" [{action_description}]" if action_description else ''
                    err_msg = f"Response{action_description} did not match the expected JSON schema. Missing expected key: {field}"
                    raise ResponseValidationError(input_var=err_msg, message=action_description)
                return False
            _dict = _dict[field]
        return True

    @property
    def playbook_ids(self):
        response = self.list_playbooks()
        return {p["id"]["id"]: p["name"] for p in response}

    def __reformat_cmd_results(self, response_dict, drop_hidden_columns=True):
        full_result = response_dict.copy()
        result_raw = full_result["result"]
        warnings = full_result["result"].get("warnings")
        result_with_schema = result_raw["rows"]["data"]

        if drop_hidden_columns:
            result_output = [{k: v for k, v in _result['fields'].items() if k not in ["lhub_id", "lhub_page_num"]} for _result in result_with_schema]
        else:
            result_output = [{k: v for k, v in _result['fields'].items()} for _result in result_with_schema]

        for _warning in warnings:
            self.log.debug(f"WARNING RETURNED: {_warning}")
        return result_output, warnings

    def execute_command(self, command_name, input_dict, reformat=True, result_limit=None):
        response = self.__api.execute_command({"command": command_name, "parameterValues": input_dict, "limit": result_limit})
        if not reformat:
            return response

        response, _ = self.__reformat_cmd_results(response)
        return response

    @staticmethod
    def __reformat_alert_simple(alert: dict):
        if not alert:
            return {}
        alert = deepcopy(alert)
        # From this: {"displayName": "batch_start_millis", "value": "1632146400000"}
        # To this: {"batch_start_millis": "1632146400000"}
        # ToDo 2022-03-09, research further and verify since m92: the step below causes a failure now, and it looks like it's because the alert API is returning cleaner results now
        # alert['additionalFields'] = {x['displayName']: x['value'] for x in alert.get('additionalFields', {}) if x.get('displayName')}

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

    def get_alert_by_id(self, alert_id, simple_format=False, included_standard_fields=None, included_additional_fields=None):
        result = self.__api.alert_fetch(alert_id)
        _ = self._result_dict_has_schema(result, "result", action_description="fetch alert", raise_errors=True)

        # Reformat alert and enrich as needed
        output = self.__enrich_alert_data(
            result['result'],
            included_standard_fields=included_standard_fields,
            included_additional_fields=included_additional_fields
        )

        # Simplify mapped and additional field output
        if simple_format:
            output = self.__reformat_alert_simple(output)
        return output

    def get_batch_results_by_id(self, batch_id: int, limit=1000, keep_additional_info=False):
        result = self.__api.get_batch_results_by_id(batch_id=batch_id, limit=limit)
        _ = self._result_dict_has_schema(result, "result", "data", raise_errors=True, action_description="get batch results by batch ID")
        result = result["result"]["data"]
        if not keep_additional_info:
            result = [r["columns"] for r in result]
        return result

    def get_batches_by_stream_id(self, stream_id: int, limit=None, statuses=None, exclude_empty_results=False):
        """
        Get all batches for a given stream

        :param stream_id: ID of the stream
        :param limit: Optional: set a batch limit (default it unlimited, despite the fact that the API's actual default is 25)
        :param statuses: Optional: List of statuses to include in the results
        :param exclude_empty_results: Optional: exclude successful batches which did not output any data
        :return: Batch results in the form of a list of dicts
        """
        result = self.__api.get_batches_by_stream_id(stream_id, limit=limit or -1, statuses=statuses, exclude_empty_results=exclude_empty_results)
        _ = self._result_dict_has_schema(result, "result", "data", raise_errors=True, action_description="get batches by stream ID")
        return result["result"]["data"]

    def get_case_prefix(self):
        return self.__api.case_prefix

    # ToDo Token auth not supported as of 2022-03-09 (m92)
    def get_dashboard_data(self, dashboard_id):
        result = self.__api.get_dashboard_data(dashboard_id.strip())
        _ = self._result_dict_has_schema(result, "result", "widgets", raise_errors=True, action_description="get dashboard data")
        result = result['result']['widgets']
        return result

    def get_notebooks_attached_to_case(self, case_id):
        response = self.__api.case_list_attached_notebooks(case_id)
        _ = self._result_dict_has_schema(response, "result", action_description="get notebooks from case", raise_errors=True)
        return response.get('result', [])

    # ToDo This finally works as of m91. Add an action for it.
    def get_stream_by_id(self, stream_id: int):
        result = self.__api.get_stream_by_id(stream_id)
        return result["result"]

    def get_version(self):
        return self.__api.version_info

    def get_workflow_by_id(self, workflow_id):
        if isinstance(workflow_id, str):
            workflow_id = re.findall(r"(\d+)", workflow_id)
            if not workflow_id:
                raise InvalidWorkflowIdFormat(input_var=workflow_id)
            workflow_id = workflow_id[0]
        workflow_id = int(workflow_id)
        result = self.__api.get_workflow_by_id(workflow_id=workflow_id)
        _ = self._result_dict_has_schema(result, "result", raise_errors=True, action_description="get workflow by ID")
        return result["result"]

    def list_baselines(self):
        result = self.__api.list_baselines()
        _ = self._result_dict_has_schema(result, "result", "data", "data", raise_errors=True, action_description="list baselines")
        result = result["result"]["data"]
        baselines = result['data']
        stream_ids = [int(b['id']['id']) for b in baselines]
        stream_state_response = self.__api.list_stream_states(stream_ids=stream_ids)
        _ = self._result_dict_has_schema(stream_state_response, "result", "streams", raise_errors=True, action_description="list stream states")
        state_map = {_stream['streamId']: _stream['status'] for _stream in stream_state_response['result']['streams']}
        for n in range(len(baselines)):
            b = baselines[n]
            _id = int(b['id']['id'])
            baselines[n]['baseline_config_status'] = state_map.get(f"stream-{b['id']['id']}")
        return result

    @staticmethod
    def __reformat_command_simple(result):
        result = {
            "name": result["name"],
            "id": int(result["id"]["id"]),
            "flowId": result["flowId"],
            "owner": result["owner"],
            "last_updated": epoch_time_to_str(result["lastUpdated"] / 1000),
            "command_status": result["commandStatus"],
        }
        return result

    def list_commands(self, filters: list = None, limit: int = None, simple_format=False):
        result = self.__api.list_commands(filters=filters, limit=limit, offset=0)
        _ = self._result_dict_has_schema(result, "result", "data", "data", action_description="list commands", raise_errors=True)
        results = result["result"]["data"]
        self.log.debug(f"{len(results)} commands found")
        if simple_format:
            results = [self.__reformat_command_simple(r) for r in results['data']]
        return results

    def list_connections(self, filters=None, add_status=False):
        result = self.__api.list_connections(filters=filters)
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list connections", raise_errors=True)
        result = result["result"]["data"]
        if not add_status:
            return result

        connections = result["data"]
        connection_ids = [connection["id"]["id"] for connection in connections]
        status_results = self.__api.get_connection_status(connection_ids)
        statuses = {status["connectionEntityId"].replace("connection-", ''): status["status"] for status in status_results['result']}
        for n in range(len(connections)):
            connection = connections[n]
            connection_id = str(connection["id"]["id"])
            connection["status"] = statuses.get(connection_id)
            if not connection["status"]:
                raise BaseAppError(f"Connection ID {connection_id} missing from status list")
        return result

    def list_custom_lists(self, search_text: str = None, filters: list = None, limit: int = None, offset: int = None):
        results = self.__api.list_custom_lists(search_text=search_text, filters=filters, limit=limit, offset=offset, verify_results=False)
        warnings = []
        try:
            results = results["result"]["data"]
        except KeyError:
            warnings.append("API response does not match the expected schema for listing custom lists")
        return results, warnings

    # ToDo Token auth not supported as of 2022-03-09 (m92)
    def list_dashboards(self):
        result = self.__api.list_dashboards()
        _ = self._result_dict_has_schema(result, "result", raise_errors=True, action_description="list dashboards")
        result = result['result']
        return result

    def list_dashboards_with_widgets(self, include_not_imported=True):
        result = self.__api.list_dashboards_with_widgets()
        _ = self._result_dict_has_schema(result, "result", "objects", raise_errors=True, action_description="list dashboards with widgets")
        result = result['result']['objects']
        if not include_not_imported:
            result = [r for r in result if r['metadata']["contentRepoStatus"] != "Global"]
        return result

    def list_fields(self, map_mode=None):
        assert not map_mode or map_mode in ['id', 'name'], f'Invalid output format: {map_mode}'
        response = self.__api.fields
        _ = self._result_dict_has_schema(response, "result", "data", raise_errors=True, action_description="list fields")
        output = response["result"]["data"]
        if map_mode == "id":
            output = {f['id']: {k: v for k, v in f.items() if k != 'id'} for f in output}
        elif map_mode == "name":
            output = {f['fieldName']: {k: v for k, v in f.items() if k != 'fieldName'} for f in output}
        return output

    def list_integrations(self, name_filter: str = None, filter_type="contains"):
        filter_type = filter_type.lower()
        assert filter_type in ["equals", "contains"], f"Invalid filter type \"{filter_type}\""

        response = self.__api.list_integrations()
        _ = self._result_dict_has_schema(response, "result", "objects")
        result = response.pop("result")
        categories = result["categories"]
        results = result["objects"]

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

    def list_modules(self, local_only=False):
        result = self.__api.list_modules()
        _ = self._result_dict_has_schema(result, "result", "objects", action_description="list modules", raise_errors=True)
        other_details = result["result"]
        modules = other_details.pop('objects')

        # If local_only is set to True, only return the modules with a contentRepoStatus of "Local"
        if local_only is True:
            modules = [x for x in modules if x['metadata']['contentRepoStatus'].lower() == 'local']

        return modules, other_details

    def list_notebooks(self):
        result = self.__api.list_notebooks()
        _ = self._result_dict_has_schema(result, "result", "data", "data", action_description="list notebooks", raise_errors=True)
        return result["result"]["data"]

    def list_playbooks(self, limit=None, map_mode=None):
        assert not map_mode or map_mode in ['id', 'name'], f'Invalid output format: {map_mode}'
        response = self.__api.list_playbooks(limit=limit)
        _ = self._result_dict_has_schema(response, "result", "data", "data")
        output = response["result"]["data"]["data"]
        if map_mode == "id":
            output = {f['id']['id']: {k: v for k, v in f.items() if k != 'id'} for f in output}
        elif map_mode == "name":
            output = {f['name']: {k: v for k, v in f.items() if k != 'name'} for f in output}
        return output

    def list_streams(self, search_text: str = None, filters: list = None, limit: int = None, offset: int = 0):
        result = self.__api.list_streams(search_text=search_text, filters=filters, limit=limit, offset=offset)
        _ = self._result_dict_has_schema(result, "result", "data", "data", raise_errors=True, action_description="list streams")
        return result["result"]["data"]["data"]

    def list_user_groups(self, hide_inactive=False):
        result = self.__api.list_user_groups(hide_inactive=hide_inactive)
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list user groups", raise_errors=True)
        return result["result"]

    @staticmethod
    def __reformat_user_simple(user: dict):
        groups = [g['name'] for g in user['groups'] if not g.get("isDeleted", False)]
        user_attributes = {
            "username": user.get("name"),
            "is_admin": user["role"]["value"] == "admin",
            "groups": ', '.join(groups),
            "email": user.get("email"),
            "is_deleted": user.get("isDeleted"),
            "is_enabled": user.get("isEnabled"),
            "auth_type": user.get("authenticationType"),
            "id": user.get("userId"),
        }
        # would it be beneficial to make a class object for these instead of returning a dict?
        return user_attributes

    # ToDo Check whether the LogicHub integration sets hide_inactive. If it won't be impacted, change the default to True.
    def list_users(self, hide_inactive=False, simple_format=False):
        result = self.__api.list_users(hide_inactive=hide_inactive)
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list users", raise_errors=True)
        results = result["result"]
        self.log.debug(f"{len(results['data'])} users found")
        if simple_format:
            results = [self.__reformat_user_simple(result) for result in results['data']]
        return results

    def list_workflows(self):
        result = self.__api.list_workflows()
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list workflows", raise_errors=True)
        return result["result"]["data"]

    def reprocess_batch(self, batch_id):
        return self.__api.reprocess_batch(batch_id)

    def attach_notebooks_to_case(self, case_id, notebook_ids):
        current_notebooks = self.__api.case_list_attached_notebooks(case_id, results_only=True)
        current_notebooks = [notebook['id'] for notebook in current_notebooks]
        new_notebooks = format_notebook_ids(notebook_ids)
        updated_notebooks = current_notebooks + [x for x in new_notebooks if x not in current_notebooks]
        if current_notebooks == updated_notebooks:
            return {"result": "no changes made"}
        return self.__api.case_overwrite_attached_notebooks(case_id, updated_notebooks)

    def detach_notebooks_from_case(self, case_id, notebook_ids):
        current_notebooks = self.__api.case_list_attached_notebooks(case_id, results_only=True)
        if not current_notebooks:
            return {"result": "no changes made"}
        # Reformat to match
        current_notebooks = format_notebook_ids(current_notebooks)
        new_notebooks = format_notebook_ids(notebook_ids)
        updated_notebooks = [notebook for notebook in current_notebooks if notebook['id'] not in [x['id'] for x in new_notebooks]]
        if current_notebooks == updated_notebooks:
            return {"result": "no changes made"}
        return self.__api.case_overwrite_attached_notebooks(case_id, updated_notebooks)

    def remove_all_notebooks_from_case(self, case_id):
        current_notebooks = self.__api.case_list_attached_notebooks(case_id, results_only=True)
        if not current_notebooks:
            return {"result": "no changes made"}
        return self.__api.case_overwrite_attached_notebooks(case_id, [])

    # ToDo Add an action for basic search as well
    def search_alerts_advanced(self, query: str = None, limit: int = None, fetch_details=None, included_standard_fields=None, included_additional_fields=None):
        simple_format = False
        if fetch_details:
            if fetch_details == 'simple':
                simple_format = True
            elif fetch_details != 'standard':
                raise InputValidationError(input_var=fetch_details, action_description="fetch_details")
        query = query.strip() if query and query.strip() else ""
        result = self.__api.alerts_search_advanced(query=query, limit=limit)
        _ = self._result_dict_has_schema(result, "result", action_description="search alerts", raise_errors=True)
        output = result['result']
        if fetch_details:
            alerts = [x['id'] for x in output['data']]
            return [
                self.get_alert_by_id(alert, simple_format=simple_format, included_standard_fields=included_standard_fields, included_additional_fields=included_additional_fields)
                for alert in alerts
            ]
        return output

    def pause_stream(self, stream_id):
        result = self.__api.stream_pause(stream_id=stream_id)
        _ = self._result_dict_has_schema(result, "result", action_description="pause stream", raise_errors=True, accept_null=True)
        return result

    def resume_stream(self, stream_id):
        result = self.__api.stream_resume(stream_id=stream_id)
        _ = self._result_dict_has_schema(result, "result", action_description="resume stream", raise_errors=True, accept_null=True)
        return result


class LogicHub:
    verify_ssl = True

    def __init__(
            self, hostname, api_key=None, username=None, password=None,
            verify_ssl=True, cache_seconds=None, verify_api_auth=True,
            logger: Logger = None, log_level=None, default_timeout=None,
            **kwargs):
        # If the LogicHubAPI class object has not been given a logger by the time this class is instantiated, set one for it
        LogicHubAPI.log = LogicHubAPI.log or logger or Logger()
        if log_level:
            LogicHubAPI.log.log_level = log_level

        LogicHubAPI.verify_ssl = self.verify_ssl

        self.kwargs = kwargs
        self.api = LogicHubAPI(hostname=hostname, api_key=api_key, username=username, password=password, verify_ssl=verify_ssl, cache_seconds=cache_seconds, default_timeout=default_timeout, **kwargs)
        self.actions = Actions(self.api)
        if verify_api_auth:
            _ = self._verify_api_auth()

    def _verify_api_auth(self):
        _ = self.api.me()
        return True
