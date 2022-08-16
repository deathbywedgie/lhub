import json
import re
from copy import deepcopy

from .api import LogicHubAPI
from .common import helpers
from .common.time import epoch_time_to_str
from .exceptions.app import BaseAppError, UserGroupNotFound, UserNotFound, UnexpectedOutput
from .exceptions.validation import InputValidationError, ResponseValidationError
from .exceptions.formatting import InvalidWorkflowIdFormat
from .log import prep_generic_logger
from logging import getLogger, RootLogger
from typing import Union

log = getLogger(__name__)


class Actions:

    def __init__(self, api: LogicHubAPI):
        self.__api = api

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

    @staticmethod
    def __reformat_cmd_results(response_dict, drop_hidden_columns=True):
        full_result = response_dict.copy()
        result_raw = full_result["result"]
        warnings = full_result["result"].get("warnings")
        result_with_schema = result_raw["rows"]["data"]

        if drop_hidden_columns:
            result_output = [{k: v for k, v in _result['fields'].items() if k not in ["lhub_id", "lhub_page_num"]} for _result in result_with_schema]
        else:
            result_output = [{k: v for k, v in _result['fields'].items()} for _result in result_with_schema]

        for _warning in warnings:
            log.warning(f"Warning returned: {_warning}")
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

    def get_connection_status_by_id(self, connection_ids: list):
        connection_ids = list(set([helpers.format_connection_id(c) for c in connection_ids]))
        status_results = self.__api.get_connection_status(connection_ids)
        statuses = {helpers.format_connection_id(status["connectionEntityId"]): status["status"] for status in status_results['result']}
        return statuses

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

    def list_stream_states(self, stream_ids, include_recent_batches=True, return_as_simple_dict=False):
        stream_ids = helpers.format_stream_id(stream_ids)
        result = self.__api.list_stream_states(stream_ids=stream_ids)
        _ = self._result_dict_has_schema(result, "result", "streams", raise_errors=True, action_description="get stream states")
        results = result['result']['streams']
        if return_as_simple_dict:
            return {r["streamId"]: r["status"] for r in results}
        if not include_recent_batches:
            for n in range(len(results)):
                _stream_id = results[n]['streamId']
                if 'data' in results[n]:
                    del results[n]['data']
                else:
                    log.warning(f"Expected recent batches in 'data' key of stream state, but no such key was found for stream {_stream_id}")
        return results

    def list_baselines(self, verify_stream_states=False):
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

        if verify_stream_states is True:
            self.__update_stream_results_with_status(result["data"])
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
        log.debug(f"{len(results)} command{'s' if len(results) != 1 else ''} found")
        if simple_format:
            results = [self.__reformat_command_simple(r) for r in results['data']]
        return results

    def list_case_types(self, limit: int = None, after: int = None, exclude_deprecated: bool = None):
        result = self.__api.list_case_types(limit=limit, after=after, exclude_deprecated=exclude_deprecated)
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list case types", raise_errors=True)
        result = result["result"]["data"]
        return result

    def list_connections(self, filters=None, add_status=False):
        result = self.__api.list_connections(filters=filters)
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list connections", raise_errors=True)
        result = result["result"]["data"]
        if not add_status:
            return result

        connections = result["data"]
        connection_ids = [connection["id"]["id"] for connection in connections]
        statuses = self.get_connection_status_by_id(connection_ids)
        for n in range(len(connections)):
            connection = connections[n]
            connection_id = int(connection["id"]["id"])
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

    def list_event_types(self, limit=None, wait_for_connection_status=False):
        results = self.__api.list_event_types(limit=limit)
        if not wait_for_connection_status:
            return results
        connection_ids = []
        for r in results:
            try:
                connection_ids.append(f'connection-{helpers.format_connection_id(r["origin"]["id"]["id"])}')
            except KeyError:
                pass
        statuses = self.get_connection_status_by_id(list(set(connection_ids)))
        for r in results:
            try:
                if r["origin"]["id"]["id"]:
                    r["origin"]["connectionStatus"] = r["eventTypeConnectionStatus"] = statuses[int(r["origin"]["id"]["id"])]
            except KeyError:
                pass
        return results

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

    def get_playbook_versions(self, playbook_id, **kwargs):
        response = self.__api.get_playbook_versions(playbook_id=playbook_id, **kwargs)
        _ = self._result_dict_has_schema(response, "result", "data")
        return response["result"]["data"]

    def list_saml_configs(self):
        result = self.__api.list_saml_configs()
        _ = self._result_dict_has_schema(result, "result", raise_errors=True, action_description="list SAML configs")
        return result["result"]

    def __update_stream_results_with_status(self, results):
        id_list = helpers.format_stream_id(results)
        states = self.list_stream_states(stream_ids=id_list, include_recent_batches=False, return_as_simple_dict=True)
        for r in results:
            if not r.get('id') or not r['id'].get('id'):
                raise UnexpectedOutput(f"stream dict did not match expected format: {r}")
            _id_str = f"stream-{r['id']['id']}"
            _id_str = f"stream-{r['id']['id']}"
            if not states.get(_id_str):
                raise UnexpectedOutput(f"{_id_str} was returned in the stream search but was not present in state search results")
            r['streamStatus'] = states[_id_str]

    def list_streams(self, search_text: str = None, filters: list = None, limit: int = None, offset: int = 0, verify_stream_states=False):
        """
        List all streams (or streams matching a search filter)

        :param search_text: Partial or full name of the streams to return
        :param filters: Other search filters (see the streams API)
        :param limit: Limit the number of results to return
        :param offset: For pagination, provide the page number of results to return
        :param verify_stream_states: The streams API does not wait for stream status
        calculation to complete unless status is part of the search filter. Enabling
        this option will fetch the true state for every stream returned before returning results.
        :param return_as_simple_dict: Return a simple dict instead, with stream IDs as keys and their respective statuses as values.
        :return:
        """
        result = self.__api.list_streams(search_text=search_text, filters=filters, limit=limit, offset=offset)
        # ToDo get accurate states with actions.list_stream_states
        # ToDo file a bug for the streams api returning incorrect states
        _ = self._result_dict_has_schema(result, "result", "data", "data", raise_errors=True, action_description="list streams")
        results = result["result"]["data"]["data"]
        if verify_stream_states is True:
            self.__update_stream_results_with_status(results)

        return results

    def list_user_groups(self, hide_inactive=True):
        result = self.__api.list_user_groups(hide_inactive=hide_inactive)
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list user groups", raise_errors=True)
        return result["result"]

    @staticmethod
    def __reformat_user_simple(user: dict):
        groups = [g['name'] for g in user['groups'] if not g.get("isDeleted", False)]
        group_ids = [g['id'] for g in user['groups'] if not g.get("isDeleted", False)]
        user_attributes = {
            "username": user.get("name"),
            "is_admin": user["role"]["value"] == "admin",
            "groups": ', '.join(groups),
            "group_ids": group_ids,
            "email": user.get("email"),
            "is_deleted": user.get("isDeleted"),
            "is_enabled": user.get("isEnabled"),
            "auth_type": user.get("authenticationType"),
            "id": user.get("userId"),
        }
        # would it be beneficial to make a class object for these instead of returning a dict?
        return user_attributes

    def list_users(self, hide_inactive=True, simple_format=False, **filters):
        if not filters:
            if self.__api.major_version < 96:
                filters = {"hide_inactive": hide_inactive}
            else:
                filters["inactiveUsers"] = "all"
                if hide_inactive is True:
                    filters["inactiveUsers"] = "onlyActive"

        result = self.__api.list_users(**filters)
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list users", raise_errors=True)
        results = result["result"]
        result_count = len(results['data'])
        log.debug(f"{result_count} user{'s' if result_count != 0 else ''} found")
        if simple_format:
            results = [self.__reformat_user_simple(result) for result in results['data']]
        return results

    def reset_password(self, user_id):
        user_id = helpers.format_user_id(user_id)
        username = self.__api.formatted.get_username_by_id(user_id)
        log.debug(f"Resetting password for user: {username}")
        result = self.__api.reset_password(user_id=user_id)
        _ = self._result_dict_has_schema(result, "result", "password", action_description="reset password", raise_errors=True)
        return result["result"]["password"]

    def list_workflows(self):
        result = self.__api.list_workflows()
        _ = self._result_dict_has_schema(result, "result", "data", action_description="list workflows", raise_errors=True)
        return result["result"]["data"]

    def reprocess_batch(self, batch_id):
        return self.__api.reprocess_batch(batch_id)

    def attach_notebooks_to_case(self, case_id, notebook_ids):
        current_notebooks = self.__api.case_list_attached_notebooks(case_id, results_only=True)
        current_notebooks = [notebook['id'] for notebook in current_notebooks]
        new_notebooks = helpers.format_notebook_ids(notebook_ids)
        updated_notebooks = current_notebooks + [x for x in new_notebooks if x not in current_notebooks]
        if current_notebooks == updated_notebooks:
            return {"result": "no changes made"}
        return self.__api.case_overwrite_attached_notebooks(case_id, updated_notebooks)

    def detach_notebooks_from_case(self, case_id, notebook_ids):
        current_notebooks = self.__api.case_list_attached_notebooks(case_id, results_only=True)
        if not current_notebooks:
            return {"result": "no changes made"}
        # Reformat to match
        current_notebooks = helpers.format_notebook_ids(current_notebooks)
        new_notebooks = helpers.format_notebook_ids(notebook_ids)
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

    # ToDo Expand on this. Offer a simple format, fetch details, etc.
    def search_cases_advanced(self, query: str = None, limit: int = None, **kwargs):
        # Validate the query first, just as the UI would do
        self.__api.cases_search_validate(query)

        result = self.__api.case_search_advanced(query=query, limit=limit, **kwargs)
        _ = self._result_dict_has_schema(result, "result", "data", action_description="search cases", raise_errors=True)
        return result["result"]["data"]

    def pause_stream(self, stream_id):
        result = self.__api.stream_pause(stream_id=stream_id)
        _ = self._result_dict_has_schema(result, "result", action_description="pause stream", raise_errors=True, accept_null=True)
        return result

    def resume_stream(self, stream_id):
        result = self.__api.stream_resume(stream_id=stream_id)
        _ = self._result_dict_has_schema(result, "result", action_description="resume stream", raise_errors=True, accept_null=True)
        return result

    def update_current_user_preferences(self, **kwargs):
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        if not kwargs:
            raise InputValidationError(
                input_var=kwargs, action_description="updating user preferences",
                message=f"Invalid input for updating user preferences. At least one ID with boolean value is required, but none were received."
            )
        for k, v in kwargs.items():
            if not isinstance(v, bool):
                raise InputValidationError(input_var=v, action_description="updating user preference", message=f"Invalid input for updating user preferences. Preference values must be boolean but received: {v}")
        preferences = self.__api.me()['result']['preferences']
        preference_ids = [p['id'] for p in preferences]
        for k in kwargs:
            if k not in preference_ids:
                raise InputValidationError(input_var=k, action_description="updating user preference", message=f"Invalid preference ID: {k}. Valid IDs are: {', '.join(preference_ids)}")
        for n in range(len(preferences)):
            if preferences[n]['id'] in kwargs:
                preferences[n]['value'] = kwargs[preferences[n]['id']]

        return self.__api.update_current_user_preferences(preferences)

    def create_user(self, username, email, authentication_type=None, group_names: list = None, group_ids: list = None):
        """
        Create a new LogicHub user

        :param username:
        :param email:
        :param authentication_type:
        :param group_names: ignored if group_ids is present
        :param group_ids:
        :return:
        """
        authentication_type = authentication_type or "password"
        if authentication_type != "password" and not isinstance(authentication_type, dict):
            raise InputValidationError(input_var=authentication_type, action_description="authentication type")
        if not group_ids:
            _groups = self.__api.formatted.user_groups_by_name
            if group_names:
                group_ids = []
                for g in group_names:
                    if g not in _groups:
                        raise UserGroupNotFound(input_var=g)
                    _group_id = helpers.format_user_group_id(_groups[g])
                    log.debug(f"Translated group {g} to ID {_group_id}")
                    group_ids.append(_group_id)
            else:
                group_ids = _groups["Everyone"]

        kwargs = {"username": username, "email": email, "authentication_type": authentication_type, "group_ids": group_ids}
        log.debug(f"Creating user: {json.dumps(kwargs)}")
        response = self.__api.create_user(**kwargs)
        return response['result']

    def delete_user_by_id(self, user_ids: Union[str, list]):
        if not isinstance(user_ids, list):
            user_ids = [user_ids]
        user_ids = [helpers.format_user_id(u) for u in user_ids]
        return self.__api.delete_user(user_ids=user_ids)

    def delete_user_by_name(self, usernames: Union[str, list]):
        _users = self.__api.formatted.users_by_name
        user_ids = []
        for u in (usernames if isinstance(usernames, list) else [usernames]):
            if u not in _users:
                log.error(f"User not found: {u}")
                raise UserNotFound(user=u)
            _user_id = helpers.format_user_id(_users[u])
            log.debug(f"Translated user {u} to ID {_user_id}")
            user_ids.append(_user_id)
        return self.delete_user_by_id(user_ids=user_ids)

    def get_password_settings(self) -> dict:
        result = self.__api.get_password_settings()
        _ = self._result_dict_has_schema(result, "result", raise_errors=True, action_description="get password settings")
        return result["result"]

    def update_password_settings(self, settings_dict):
        result = self.__api.update_password_settings(settings_dict=settings_dict)
        _ = self._result_dict_has_schema(result, "result", raise_errors=True, action_description="update password settings")
        return result["result"]


class LogicHub:
    verify_ssl = True
    http_timeout_default = LogicHubAPI.http_timeout_default

    def __init__(
            self, hostname, api_key=None, username=None, password=None,
            cache_seconds=None, verify_api_auth=True, default_timeout=None, logger: RootLogger = None, log_level=None, **kwargs):
        global log
        if logger:
            log = logger
        else:
            prep_generic_logger(level=log_level)
        self.hostname = hostname
        self.kwargs = kwargs
        self.api = LogicHubAPI(
            hostname=hostname, api_key=api_key, username=username, password=password,
            cache_seconds=cache_seconds, default_timeout=default_timeout or self.http_timeout_default,
            logger=logger, **kwargs)
        self.actions = Actions(self.api)
        if verify_api_auth:
            _ = self._verify_api_auth()
        log.debug(f"LogicHub (lhub) session successfully initialized (hostname={self.hostname})")

    def _verify_api_auth(self):
        _ = self.api.me()
        log.debug(f"Authentication successful (hostname={self.hostname})")
        return True
