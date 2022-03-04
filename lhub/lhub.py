#!/usr/bin/env python3

import base64
import json
import os
import re
import sys
import time
from collections import namedtuple
from pathlib import Path

import requests
from lhub import exceptions
from copy import deepcopy

# LOGGING START -->
# eventually move back out to a separate file when it's time to finish building this as a pip installable package
_LOG_LEVEL_MAP = {"debug": 7, "info": 6, "notice": 5, "warn": 4, "error": 3, "crit": 2, "alert": 1, "fatal": 0}


# Placeholder for real logging
class Logger:
    __log_level = "INFO"
    default_log_level = "INFO"

    _LOG_LEVELS = _LOG_LEVEL_MAP.keys()

    def __init__(self, session_prefix=None, log_level=None):
        self.log_level = log_level if log_level else self.default_log_level
        # self.session_prefix = session_prefix or ""
        self.session_prefix = (session_prefix or self.generate_logger_prefix()).strip()

    def generate_logger_prefix(self):
        return f"[{hex(id(self))}] "

    @property
    def log_level(self):
        if self.__log_level.lower() not in self._LOG_LEVELS:
            raise ValueError(f"Invalid log level: {self.__log_level}")
        return self.__log_level

    @log_level.setter
    def log_level(self, val: str):
        if val.lower() not in self._LOG_LEVELS:
            raise ValueError(f"Invalid log level: {val}")
        self.__log_level = val.upper()

    def __print(self, level, msg):
        level_num = _LOG_LEVEL_MAP[level.lower()]
        output_file = sys.stdout if level_num >= 5 else sys.stderr
        current_level_num = _LOG_LEVEL_MAP[self.log_level.lower()]
        if current_level_num >= level_num:
            print(f"[{level.upper()}] {self.session_prefix} {msg}", file=output_file)
        if level_num == 0:
            sys.exit(1)

    def debug(self, msg):
        self.__print("debug", msg)

    def info(self, msg):
        self.__print("info", msg)

    def notice(self, msg):
        self.__print("notice", msg)

    def warn(self, msg):
        self.__print("warn", msg)

    def error(self, msg):
        self.__print("error", msg)

    def crit(self, msg):
        self.__print("crit", msg)

    def alert(self, msg):
        self.__print("alert", msg)

    def fatal(self, msg):
        self.__print("fatal", msg)

    @staticmethod
    def print(msg):
        """
        Explicit print option so this can be further controlled later if needed

        :param msg:
        :return:
        """
        print(msg)


class URLs:
    _version = 0

    def __init__(self, server_name):
        self.server_name = str(server_name).lower().strip()

    @property
    def base(self):
        return f"https://{self.server_name}"

    @property
    def alert_fetch(self):
        return f"{self.base}/api/alert/alert-{{}}"

    @property
    def alerts_search_advanced(self):
        return f"{self.base}/api/alert/search/advanced"

    @property
    def alerts_search_basic(self):
        return f"{self.base}/api/alert/search/basic"

    @property
    def alerts_search_validate(self):
        return f"{self.base}/api/alert/search/validate"

    @property
    def baselines(self):
        return f"{self.base}/api/content-management/content/baseline"

    @property
    def batch_reprocess(self):
        return f"{self.base}/api/demo/batch-{{}}"

    @property
    def batch_results_by_id(self):
        return f"{self.base}/api/demo/batch-{{}}/correlations"

    @property
    def _case_base_url(self):
        return f"{self.base}/api/case/{{case_id}}"

    @property
    def case_get_basic_details(self):
        return f"{self._case_base_url}/basicDetails"

    @property
    def case_get_custom_fields(self):
        return f"{self._case_base_url}/fields"

    @property
    def case_update_linked_alerts(self):
        return self._case_base_url

    @property
    def case_status_list_workflows(self):
        return f"{self.base}/api/cases/status-workflow"

    @property
    def case_status_workflow_by_id(self):
        return f"{self.base}/api/cases/status-workflow/statusworkflow-{{}}"

    @property
    def cases_get_prefix(self):
        return f"{self.base}/api/cases/prefix"

    @property
    def command(self):
        return f"{self.base}/commands/{{}}"

    @property
    def command_execute(self):
        return f"{self.base}/api/commands/execute"

    @property
    def connection_status(self):
        return f"{self.base}/api/connection/status"

    @property
    def connections(self):
        return f"{self.base}/api/content-management/content/connection"

    @property
    def custom_list_data(self):
        return f"{self.base}/api/lists/{{}}/data"

    @property
    def custom_list_data_with_filtering(self):
        return f"{self.base}/api/lists/{{}}/search"

    @property
    def custom_lists(self):
        return f"{self.base}/api/content-management/content/customList"

    @property
    def event_types(self):
        # Not sure when the old one changed, but it doesn't work in 70
        if self._version < 70:
            return f"{self.base}/api/eventtype-flowrefs"
        return f"{self.base}/api/content-management/content/eventType"

    @property
    def fields(self):
        return f"{self.base}/api/fields"

    @property
    def fields_get_computed(self):
        # Fetch the config of computed fields, i.e. lh_url, lh_filehash, and lh_ipaddress (example: regex exclusions)
        return f"{self.base}/api/fields/computed"

    @property
    def flow_export(self):
        return f"{self.base}/api/flow/{{}}/export"

    @property
    def integrations(self):
        return f"{self.base}/api/content-exchange/browse/Integration"

    @property
    def login(self):
        return f"{self.base}/api/login"

    @property
    def logout(self):
        return f"{self.base}/api/logout"

    @property
    def me(self):
        return f"{self.base}/api/user-management/me"

    @property
    def modules(self):
        return f"{self.base}/api/content-exchange/browse/Module"

    @property
    def notebooks_attach(self):
        return f"{self.base}/api/notebook/attachNotebooksToEntity"

    @property
    def notebooks_attached(self):
        return f"{self.base}/api/notebook/attachedNotebooks"

    @property
    def notebooks_list(self):
        return f"{self.base}/api/content-management/content/notebook"

    @property
    def playbooks_list(self):
        return f"{self.base}/api/content-management/content/playbook"

    @property
    def rule_set(self):
        return f"{self.base}/api/demo/ruleSet-{{}}"

    @property
    def rule_sets(self):
        return f"{self.base}/api/demo/hub/ruleSets"

    @property
    def stream_batches(self):
        return f"{self.base}/api/stream/stream-{{}}/batches/filter"

    @property
    def stream_by_id(self):
        return f"{self.base}/api/stream/stream-{{}}"

    @property
    def stream_states(self):
        return f"{self.base}/api/stream/states"

    @property
    def stream_pause(self):
        return f"{self.base}/api/stream/pause"

    @property
    def stream_resume(self):
        return f"{self.base}/api/stream/resume"

    @property
    def streams(self):
        return f"{self.base}/api/content-management/content/stream"

    @property
    def user_groups(self):
        return f"{self.base}/api/user-management/user-group/search"

    @property
    def users(self):
        return f"{self.base}/api/user-management/user/search"

    @property
    def version(self):
        return f"{self.base}/api/version"


cached_obj = namedtuple('CachedObject', ['time', 'value'])


class LogicHubAPI:
    DEFAULT_ALERT_RESULT_LIMIT = 100
    DEFAULT_CACHE_SECONDS = 300
    USER_AGENT_STRING = "lhub cli"
    http_timeout_default = 120
    verify_ssl = True
    log: Logger = None
    last_response_text = None

    __session_cookie = None
    __exit_set = False
    __version = None
    __version_info = None
    __case_prefix = None
    __fields = None
    __notebooks = None
    __api_key = None

    def __init__(self, hostname, api_key, verify_ssl=True, cache_seconds=None, **kwargs):
        self.cache_seconds = int(cache_seconds or LogicHubAPI.DEFAULT_CACHE_SECONDS)
        if self.cache_seconds is None or self.cache_seconds < 0:
            self.cache_seconds = 0

        if not self.log:
            self.log = Logger()
        self.kwargs = kwargs

        if isinstance(verify_ssl, bool):
            self.verify_ssl = verify_ssl
        if not self.verify_ssl:
            # Disable certificate warnings
            self.log.debug("Disabling SSL warnings...")
            from urllib3 import disable_warnings
            from urllib3.exceptions import InsecureRequestWarning
            disable_warnings(InsecureRequestWarning)

        self.__api_key = api_key
        self.url = URLs(hostname)
        self.url._version = self.version

    def __enter__(self):
        return self

    def __get_cached_object(self, var: cached_obj):
        """
        Special method for managing cacheable property objects.
        To use this, the property must store values using the "cached_obj" namedtuple. (See "version_info" getter and setter as an example.)

        :param var:
        :return:
        """
        if var:
            if var.time >= int(time.time()) - self.cache_seconds:
                return var.value

    @property
    def default_http_headers(self):
        headers = {"User-Agent": self.USER_AGENT_STRING}
        if self.__api_key:
            headers["X-Auth-Token"] = self.__api_key
        return headers

    @property
    def version_info(self):
        if not self.__get_cached_object(self.__version_info):
            _ = self.get_version_info()
        return self.__version_info.value

    @version_info.setter
    def version_info(self, value):
        self.__version_info = cached_obj(int(time.time()), value)

    @property
    def fields(self):
        if not self.__get_cached_object(self.__fields):
            _ = self.list_fields()
            self.log.debug(f"Updated cached property: fields (timeout: {self.cache_seconds} sec")
        return self.__fields.value

    @fields.setter
    def fields(self, value):
        self.__fields = cached_obj(int(time.time()), value)

    @property
    def system_field_lh_linked_alerts(self):
        for f in self.fields:
            if f.get('fieldName') == 'lh_linked_alerts':
                return f
        raise exceptions.Validation.VersionMinimumNotMet(min_version='m86', feature_label='linked alerts')

    @property
    def version(self):
        if not self.__get_cached_object(self.__version):
            _ = self.get_version_info()
            self.log.debug(f"LogicHub version: m{self.__version}")
        return self.__version.value

    @version.setter
    def version(self, value):
        self.__version = cached_obj(int(time.time()), value)

    @property
    def case_prefix(self):
        if not self.__get_cached_object(self.__case_prefix):
            _ = self.cases_get_prefix()
        return self.__case_prefix.value

    @case_prefix.setter
    def case_prefix(self, value):
        self.__case_prefix = cached_obj(int(time.time()), value)

    @property
    def notebooks(self):
        if not self.__get_cached_object(self.__notebooks):
            result = self.notebooks_list()
            self.notebooks = result["result"]["data"]["data"]
        return self.__notebooks.value

    @notebooks.setter
    def notebooks(self, val):
        self.__notebooks = cached_obj(int(time.time()), val)

    @property
    def notebooks_name_map(self):
        return {notebook['name']: notebook['id']['id'] for notebook in self.notebooks}

    @staticmethod
    def __standard_http_response_tests(response_obj, url):
        # Group all tests for status code 401
        if response_obj.status_code == 401:
            if 'Unauthorized for URL' in response_obj.text or 'token is not allowed with this endpoint' in response_obj.text:
                raise exceptions.Auth.APIAuthNotAuthorized(url)
            else:
                raise exceptions.Auth.APIAuthFailure(url)

        # Group all tests for status code 500
        elif response_obj.status_code == 500:
            if 'Unable to find batch with id' in response_obj.text:
                _id = re.search(r'Unable to find batch with id ([-\w]+)', response_obj.text)
                _id = _id.groups()[0] if _id else None
                raise exceptions.BatchNotFound(_id)

        response_obj.raise_for_status()

    def _http_request(
            self, url, method="GET", params: dict = None, body=None,
            headers: dict = None, timeout=None, test_response: bool = True,
            **kwargs):
        method = method.upper() if method else "GET"

        # Reset last response text
        self.last_response_text = None
        # Merge provided headers (if any) with default headers
        headers = {**self.default_http_headers, **(headers if headers else {})}
        timeout = timeout if timeout is not None else self.http_timeout_default
        json_body = None
        if isinstance(body, (dict, list)):
            json_body = body or {}
            body = None

        if method in ("POST", "PATCH") and not body and not json_body:
            body = "{}"
            json_body = {}

        kwargs = {k: v for k, v in {**{"params": params, "data": body, "json": json_body, "headers": headers}, **(kwargs or {})}.items() if v}
        response = requests.request(method=method, url=url, verify=self.verify_ssl, timeout=timeout, **kwargs)

        # Store last response before testing whether the call was successful
        try:
            self.last_response_text = response.json()
        except:
            self.last_response_text = response.text
        if test_response:
            self.__standard_http_response_tests(response, url)
        return response

    def __get_event_types_v1(self, limit):
        # Not sure when this one stopped working, but it worked somewhere in at least m66 and didn't work any more in m70
        params = {"limit": limit}
        response = self._http_request(url=self.url.event_types, params=params)
        results = response.json()
        if results.get("result"):
            results = results["result"]
        if results.get("data"):
            results = results["data"]
        return results

    def __get_event_types_v2(self, limit):
        params = {"libraryView": "all"}
        body = {"filters": [], "offset": 0, "pageSize": limit, "sortColumn": "lastUpdated", "sortOrder": "DESC"}
        response = self._http_request(method="POST", url=self.url.event_types, params=params, body=body)
        results = response.json()
        if results.get("result"):
            results = results["result"]
        while isinstance(results, dict) and results.get('data') is not None:
            results = results["data"]
        return results

    def get_event_types(self, limit=25):
        limit = int(limit or 25)
        if self.version < 70:
            return self.__get_event_types_v1(limit=limit)
        return self.__get_event_types_v2(limit=limit)

    # ToDo STILL DOES NOT WORK WITH API AUTH AS OF M91
    def get_rule_sets(self, limit=25):
        limit = int(limit or 25)
        params = {
            "fields": "name,isPublic",
            "pageSize": limit,
        }
        response = self._http_request(url=self.url.rule_sets, params=params)
        results = response.json()
        try:
            results = results["result"]["data"]
        except Exception:
            raise exceptions.UnexpectedOutput("API response does not match the expected schema for listing rule sets")
        return results

    @staticmethod
    def __sanitize_input_rule_set(rule_set_id):
        if isinstance(rule_set_id, int):
            return rule_set_id
        rule_set_num_str = re.sub(r'\D+', '', str(rule_set_id))
        if not rule_set_num_str:
            raise ValueError("Invalid rule set ID")
        return int(rule_set_num_str)

    @staticmethod
    def __sanitize_input_rule_field_mappings(field_mappings):
        if not isinstance(field_mappings, dict):
            try:
                field_mappings = json.loads(field_mappings)
            except Exception:
                raise exceptions.Formatting.InvalidRuleFormat(field_mappings)
        if not field_mappings:
            raise exceptions.Formatting.InvalidRuleFormat(field_mappings)
        return field_mappings

    @staticmethod
    def __sanitize_input_rule_score(score, round_points: int = None):
        try:
            score = float(score)
            assert 10 >= score >= 0
        except (ValueError, TypeError, AssertionError):
            raise ValueError("Score must be a number between 0 and 10")
        if round_points:
            score = round(score, round_points)
        return score

    def get_stream_by_id(self, stream_id: int):
        headers = {"Accept": "application/json"}
        response = self._http_request(url=self.url.stream_by_id.format(stream_id), headers=headers, test_response=False)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            if response.status_code == 400 and 'Cannot find entity for id StreamId' in response.text:
                raise exceptions.StreamNotFound(stream_id)
        return response.json()

    def get_stream_states(self, stream_ids: list):
        new_stream_id_list = []
        for s in stream_ids:
            new_stream_id_list.append(f'stream-{s}')
        body = {"streams": new_stream_id_list}
        response = self._http_request(method="POST", url=self.url.stream_states, body=body)
        return response.json()

    def get_batches_by_stream_id(self, stream_id, limit=25, offset=0, statuses=None, exclude_empty_results=False):
        params = {
            "pageSize": int(limit or 25),
            "after": int(offset or 0),
        }
        body = {"status": statuses or [], "excludeBatchesWithZeroEvents": exclude_empty_results}
        response = self._http_request(method="POST", url=self.url.stream_batches.format(stream_id), params=params, body=body)
        return response.json()

    def get_batch_results_by_id(self, batch_id: int, limit=1000, offset=0):
        limit = int(limit or 1000)
        offset = int(offset or 0)
        params = {"fields": "*", "pageSize": limit, "after": offset, "cachedOnly": "true"}
        response = self._http_request(url=self.url.batch_results_by_id.format(int(batch_id)), params=params)
        return response.json()

    def get_integrations(self):
        response = self._http_request(method="GET", url=self.url.integrations)
        return response.json()

    def get_streams(self, search_text: str = None, filters: list = None, limit: int = 25, offset: int = 0):
        params = {"libraryView": "all"}
        headers = {"Content-Type": "application/json"}

        filters = filters or []
        if search_text:
            filters.append({"searchText": search_text})

        body_dict = {
            "filters": filters,
            "offset": offset,
            "pageSize": limit,
            "sortColumn": "name",
            "sortOrder": "ASC"
        }

        response = self._http_request(method="POST", url=self.url.streams, body=body_dict, headers=headers, params=params)
        return response.json()

    def get_version_info(self):
        self.log.debug("Fetching LogicHub version")
        try:
            response = self._http_request(
                url=self.url.version,
                timeout=self.http_timeout_default)
            response_dict = response.json()
        except (KeyError, ValueError, TypeError, IndexError):
            raise exceptions.LhBaseException("LogicHub version could not be established")
        else:
            # Update version information any time this api call is run successfully
            self.version_info = response_dict
            self.version = float(re.match("m(.*)", self.version_info["version"]).group(1))
        return response_dict

    # ToDo STILL DOES NOT WORK WITH API AUTH AS OF M91
    def get_rules_for_rule_set(self, rule_set):
        rule_set = LogicHubAPI.__sanitize_input_rule_set(rule_set)
        params = {
            "fields": "name,isPublic,rules[filter,values*1000,score]*1000",
        }
        response = self._http_request(url=self.url.rule_set.format(rule_set), params=params)
        results = response.json()
        try:
            results = results["result"]["rules"]["data"]
        except Exception:
            raise exceptions.UnexpectedOutput("API response does not match the expected schema for listing rules of a rule set")
        return results

    # ToDo STILL DOES NOT WORK WITH API AUTH AS OF M91
    # ToDo Create an action method for this, and update the beta integration action to use it
    def add_scoring_rule(self, rule_set, field_mappings, score: float or str):
        rule_set = LogicHubAPI.__sanitize_input_rule_set(rule_set)
        field_mappings = LogicHubAPI.__sanitize_input_rule_field_mappings(field_mappings)
        score = LogicHubAPI.__sanitize_input_rule_score(score)
        headers = {"Content-Type": "application/json"}
        body = {
            "method": "addRule",
            "parameters": {
                "values": [field_mappings],
                "score": score
            }
        }
        response = self._http_request(url=self.url.rule_set.format(rule_set), method="POST", body=body, headers=headers)
        results = response.json()
        try:
            results = results["result"]
        except Exception:
            raise exceptions.UnexpectedOutput("API response does not match the expected schema for adding a scoring rule")
        return results

    def get_rule_set_by_name(self, name):
        rule_sets = self.get_rule_sets()
        rule_set = [x for x in rule_sets if x['name'] == name]
        if not rule_set:
            raise exceptions.RuleSetNotFound(f"No rule set found matching name: {name}")
        rule_set = rule_set[0]
        rule_set['rules'] = self.get_rules_for_rule_set(rule_set['id'])
        return rule_set

    def get_custom_lists(self, search_text: str = None, filters: list = None, limit: int = None, offset: int = None, verify_results=True):
        """

        :param search_text: Optional: Part or all of the custom list name to filter by
        :param filters: Optional: Advanced search, e.g. [{"searchText":"<case name>"}]
        :param limit: Optional: Limit the number of results
        :param offset: Optional: if using pagination, provide the entry number to fetch (default is 0)
        :param verify_results: Optional: set to false to return response JSON without verifying that the format is as expected
        :return:
        """
        if limit:
            assert isinstance(limit, int) or int(limit)
        if offset:
            assert isinstance(offset, int) or int(offset)
        limit = int(limit or 10_000)
        offset = int(offset or 0)
        filters = filters or []
        if search_text:
            filters.append({"searchText": search_text})

        response = self._http_request(
            method="POST",
            url=self.url.custom_lists,
            params={"libraryView": "all"},
            body={
                "filters": filters,
                "offset": offset,
                "pageSize": limit,
                "sortColumn": "name",
                "sortOrder": "ASC"
            },
            headers={'Content-Type': 'application/json'},
        )
        results = response.json()
        if verify_results:
            try:
                _ = results["result"]["data"]
            except Exception:
                raise exceptions.UnexpectedOutput("API response does not match the expected schema for listing custom lists")
        return results

    # ToDo in progress
    def get_custom_list_data(self, list_id, filter_sql: str = None, limit: int = None, offset: int = None):
        """

        :param list_id: numeric ID for requested custom list
        :param filter_sql: Optional: filter custom list data to return (spark SQL)
        :param limit: Optional: limit the number of results to return (default is 10,000)
        :param offset: Optional: if using pagination, provide the entry number to fetch (default is 0)
        :return:
        """
        assert isinstance(list_id, int) or int(list_id)
        list_id = int(list_id)
        if limit:
            assert isinstance(limit, int) or int(limit)
        if offset:
            assert isinstance(offset, int) or int(offset)
        limit = int(limit or 10_000)
        offset = int(offset or 0)
        if filter_sql:
            url = self.url.custom_list_data_with_filtering.format(list_id)
            method = "POST"
            payload = filter_sql.strip()
        else:
            url = self.url.custom_list_data
            method = "GET"
            payload = None
        response = self._http_request(
            method=method,
            url=url,
            params={"offset": offset, "limit": limit},
            body=payload,
            headers={'Content-Type': 'application/json'},
        )
        results = response.json()
        try:
            results = results["result"]
        except Exception:
            raise exceptions.UnexpectedOutput("API response does not match the expected schema for listing custom lists")
        return results

    def execute_command(self, command_payload, limit=25):
        response = self._http_request(
            url=self.url.command_execute,
            method="POST",
            body=command_payload,
            test_response=False,
            params={"pageSize": int(limit or 25)}
        )
        try:
            result_dict = response.json()
        except json.decoder.JSONDecodeError:
            self.log.fatal(f"Failed to load API response as JSON. Status code: {response.status_code} Response text: {response.text}")
            sys.exit(1)

        errors = result_dict.pop("errors", [])
        if errors:
            self.log.alert(f"Request was successful, but command failed with errors")
            self.log.debug(f"Full error list: {json.dumps(errors)}")
            self.log.debug(f"Other error response data: {json.dumps(result_dict)}")
            try:
                self.log.alert(f"Direct link to command: {self.url.command.format(errors[0]['details']['flowId'])}")
            except KeyError:
                pass
            for error in errors:
                error_type = error.pop("errorType", None)
                error_msg = error.pop("message", None)
                error_details = json.dumps(error.pop("details", None))
                if error_details:
                    # Example error output:
                    # [DEBUG] [0x10f00cef0] Command error details: {"msg": "[Execution Error] Executing node final_output failed. [Error Executing Operator: select].
                    #   <<(lhub_file_id,None)>> does not exist in the table.", "flowId": "flow-1019", "nodeId": "ac4ce79f-d6d4-40fc-b855-77086fca92d5",
                    #   "causes": ["lql.LqlValidator$OperatorException: [Error Executing Operator: select]", "java.lang.IllegalArgumentException:
                    #   <<(lhub_file_id,None)>> does not exist in the table."]}
                    self.log.debug(f"Command error details: {error_details}")

                if error:
                    # [DEBUG] [0x10f00cef0] Additional error fields: {"cause": "lql.LqlValidator$OperatorException: [Error Executing Operator: select]"}
                    self.log.debug(f"Additional error fields: {json.dumps(error)}")

                # [FATAL] [0x11dc8b400] Command returned error (SparkRuntimeException): [Execution Error] Executing node final_output failed.
                # [Error Executing Operator: select]. <<(lhub_file_id,None)>> does not exist in the table.
                self.log.error(f"Command returned error ({error_type}): {error_msg}")
            sys.exit(1)

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            message = f"Request failed with status code {response.status_code}\n\nText:\n\n"
            try:
                message += json.dumps(response.json(), indent=2)
            except (json.decoder.JSONDecodeError, ValueError, TypeError):
                message += response.text
            self.log.fatal(message)
        return response.json()

    def _get_playbook_ids(self, limit=25):
        limit = int(limit or 25)
        body = {"filters": [], "offset": 0, "pageSize": limit, "sortColumn": "name", "sortOrder": "ASC"}
        response = self._http_request(
            url=self.url.playbooks_list,
            method="POST",
            params={"pageSize": limit},
            body=body
        )
        playbooks = response.json()["result"]["data"]["data"]
        return {p["id"]["id"]: p["name"] for p in playbooks}

    def _set_export_path(self, parent_folder, export_type):
        current_date = time.strftime("%Y-%m-%d")
        _folder_counter = 0
        while True:
            _folder_counter += 1
            _new_export_folder = os.path.join(parent_folder, f"{self.url.server_name}_{export_type}_{current_date}_{_folder_counter}")
            if not os.path.exists(_new_export_folder) or not os.listdir(_new_export_folder):
                parent_folder = _new_export_folder
                path = Path(parent_folder)
                path.mkdir(parents=True, exist_ok=True)
                break
        return parent_folder

    def _save_export_to_disk(self, response, export_folder, resource_id, resource_name, file_info):
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            warning = f"{file_info} - Download FAILED"
            _response_message = {}
            if response.text:
                try:
                    _response_message = json.loads(response.text)
                except json.decoder.JSONDecodeError:
                    pass

            if not _response_message.get("errors"):
                self.log.error(warning + f': unknown failure (status code {response.status_code})')
            else:
                error = _response_message.get("errors")[0]
                warning += f": {error['errorType']}: {error['message']}"
                self.log.error(warning)
                with open(os.path.join(export_folder, "_FAILURES.log"), "a+") as _error_file:
                    _error_file.write(warning + "\n")
        else:
            write_mode = "w"
            content_b64 = response.json()["result"]["contentB64"]
            file_type = response.json()["result"]["fileType"]
            file_name = f"{resource_name}.{file_type}"
            if file_type == "json":
                decoded = base64.b64decode(content_b64).decode("utf-8")
                file_data = json.dumps(json.loads(decoded), indent=4)
            elif file_type == "zip":
                write_mode = "wb"
                file_data = base64.b64decode(content_b64)
            else:
                # Should never happen, but just in case...
                raise exceptions.LhBaseException(f"\nERROR: Unknown file type. You will need to download manually: {resource_name} ({resource_id})")

            with open(os.path.join(export_folder, file_name), write_mode) as _file:
                _file.write(file_data)
            self.log.info(f"{file_info} - Saved successfully")

    def export_flows(self, export_folder, limit=None):
        limit = int(limit if limit and int(limit) and limit >= 1 else 99999)
        export_folder = self._set_export_path(parent_folder=export_folder, export_type="flows")

        flow_ids = self._get_playbook_ids(limit=limit)
        flow_ids_list = sorted(list(flow_ids.keys()))
        for n in range(len(flow_ids_list)):
            _flow_id = flow_ids_list[n]
            _flow_name = flow_ids[_flow_id]

            _file_info = f"{n + 1} of {len(flow_ids_list)}: {_flow_id} ({_flow_name})"
            self.log.info(f"{_file_info} - Downloading...")
            _response = self._http_request(url=self.url.flow_export.format(_flow_id), test_response=False)
            self._save_export_to_disk(response=_response, export_folder=export_folder, resource_id=_flow_id, resource_name=_flow_name, file_info=_file_info)

    def get_workflows(self):
        response = self._http_request(method="GET", url=self.url.case_status_list_workflows)
        return response.json()

    def get_workflow_by_id(self, workflow_id: int):
        assert isinstance(workflow_id, int), "Workflow ID must be an integer"
        response = self._http_request(method="GET", url=self.url.case_status_workflow_by_id.format(workflow_id))
        return response.json()

    def list_baselines(self):
        params = {"libraryView": "all"}
        body = {"filters": [], "offset": 0, "pageSize": 9999, "sortColumn": "lastUpdated", "sortOrder": "DESC"}
        response = self._http_request(method="POST", url=self.url.baselines, params=params, body=body)
        return response.json()

    def list_connections(self, limit=None, filters=None, offset=0):
        limit = int(limit if limit and int(limit) and limit >= 1 else 99999)
        params = {"libraryView": "all"}
        headers = {"Content-Type": "application/json"}
        body = {"filters": filters or [], "offset": offset, "pageSize": limit, "sortColumn": "name", "sortOrder": "ASC"}
        response = self._http_request(method="POST", url=self.url.connections, headers=headers, params=params, body=body)
        return response.json()

    def list_fields(self, params: dict = None, **kwargs):
        params = params or {"systemFields": "true", "pageSize": 9999, "after": 0}
        response = self._http_request(method="GET", url=self.url.fields, params=params, **kwargs)
        self.fields = response.json()
        return response.json()

    def list_modules(self):
        response = self._http_request(
            method="GET",
            url=self.url.modules,
            headers={"Content-Type": "application/json"}
        )
        return response.json()

    def get_connection_status(self, connections: list):
        """
        Get status of one or more connections
        :param connections: list of connection IDs, either as ints (like [6, 8]) or in full form (like ["connection-6", "connection-8"])
        :return:
        """
        connection_list = []
        if not isinstance(connections, (list, tuple)):
            connections = [connections]
        for connection in connections:
            if isinstance(connection, str) and connection.startswith("connection-"):
                connection_list.append(connection)
            else:
                connection_list.append(f"connection-{connection}")

        headers = {"Content-Type": "application/json"}
        # response = self._http_request(method="POST", url=self.url.connection_status, headers=headers, body=json.dumps(connection_list))
        response = self._http_request(method="POST", url=self.url.connection_status, headers=headers, body=connection_list)
        return response.json()

    # ToDo Revisit and finish this
    # def get_alerts(self, advanced_filter=None, limit=100):
    #     limit = int(limit) if limit is not None else 100_000
    #     body = {
    #         "pageNumber": 0,
    #         "pageSize": limit,
    #         "query": advanced_filter,
    #         "sortCol": "id",
    #         "sortOrder": "desc"
    #     }
    #     connection_list = []
    #     if not isinstance(connections, (list, tuple)):
    #         connections = [connections]
    #     for connection in connections:
    #         if isinstance(connection, str) and connection.startswith("connection-"):
    #             connection_list.append(connection)
    #         else:
    #             connection_list.append(f"connection-{connection}")
    #
    #     headers = {"Content-Type": "application/json"}
    #     # response = self._http_request(method="POST", url=self.url.connection_status, headers=headers, body=json.dumps(connection_list))
    #     response = self._http_request(method="POST", url=self.url.connection_status, headers=headers, body=connection_list)
    #     return response.json()

    def reprocess_batch(self, batch_id):
        """
        Reprocess an errored, canceled, or stale batch using its batch ID

        :param batch_id:
        :return:
        """
        if str(batch_id).startswith("batch"):
            batch_id = int(re.sub(r'\D+', '', str(batch_id)))
        headers = {"Content-Type": "application/json"}
        body = {"method": "reschedule", "parameters": {}}
        response = self._http_request(method="POST", url=self.url.batch_reprocess.format(batch_id), headers=headers, body=body)
        return response.json()

    def me(self):
        response = self._http_request(method="GET", url=self.url.me, timeout=30)
        return response.json()

    def case_prefix_refresh(self):
        _ = self.cases_get_prefix()
        return self.case_prefix

    # ToDo Revisit eventually. Aborted on 2022-02-22 because it turns out this can be set w/ the case management integration as a custom field
    # def case_link_alerts(self, case_id, alert_ids):
    #     if not isinstance(alert_ids, list):
    #         alert_ids = [alert_ids]
    #     updated_alerts = []
    #     for i in alert_ids:
    #         i = self._format_alert_id(i)
    #         if i:
    #             updated_alerts.append(i)
    #     alert_ids = updated_alerts
    #
    #     case_id = self._format_case_id(case_id)
    #
    #     field_id = self.system_field_lh_linked_alerts.get('id')
    #     body = {"fields": [{"id": field_id, "value": alert_ids}]}
    #     response = self._http_request(
    #         method="PATCH",
    #         url=self.url.case_update_linked_alerts.format(case_id=case_id),
    #         headers={"Content-Type": "application/json"}
    #     )
    #     output = response.json()

    def cases_get_prefix(self):
        response = self._http_request(
            url=self.url.cases_get_prefix,
            headers={"Content-Type": "application/json"}
        )
        output = response.json()
        self.case_prefix = output['result']
        return output

    @staticmethod
    def __sort_notebook_objects_by_id(notebooks):
        return sorted(notebooks, key=lambda x: (x['id']['id']))

    def case_list_attached_notebooks(self, case_id, results_only=False):
        case_id = self._format_case_id(case_id)
        body = {
            "id": case_id,
            "key": "case",
        }
        response = self._http_request(
            url=self.url.notebooks_attached,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=body
        )
        response = response.json()
        # Sort the results by notebook ID
        results = response['result'] = self.__sort_notebook_objects_by_id(response['result'])
        if results_only:
            for n in range(len(results)):
                results[n]['id']['id'] = int(results[n]['id']['id'])
            return results
        return response

    def notebooks_list(self, limit=None, search_string=None):
        limit = limit if limit and isinstance(limit, int) else 99999
        body = {
            "filters": [],
            "offset": 0,
            "pageSize": limit,
            "sortColumn": "name",
            "sortOrder": "ASC",
        }
        if search_string:
            body['filters'] = [{"searchText": search_string}]
        response = self._http_request(
            url=self.url.notebooks_list,
            method="POST",
            headers={"Content-Type": "application/json"},
            params={"libraryView": "all"},
            body=body
        )
        response = response.json()
        # Sort the results by notebook ID
        self.notebooks = response["result"]["data"]["data"] = self.__sort_notebook_objects_by_id(response["result"]["data"]["data"])
        return response

    @staticmethod
    def _format_alert_id(alert_id):
        if isinstance(alert_id, str):
            if not re.match(r'^(?:alert-)?\d+$', alert_id):
                raise exceptions.Formatting.InvalidAlertIdFormat(alert_id)
            alert_id = re.sub(r'\D+', '', alert_id)
        return int(alert_id)

    def _format_case_id(self, case_id):
        if not case_id:
            raise ValueError("Case ID cannot be blank")
        case_id = str(case_id).strip()
        if '-' not in case_id:
            case_id = f"{self.case_prefix}-{case_id}"
        return case_id

    @staticmethod
    def _format_notebook_ids(notebook_ids):
        if not isinstance(notebook_ids, list):
            notebook_ids = [notebook_ids]
        final_notebooks = []
        for input_value in notebook_ids:
            if isinstance(input_value, dict):
                # In case a raw notebook object is passed, drill into the 'id' field for the part we need
                if isinstance(input_value, dict) and isinstance(input_value.get('id'), dict):
                    input_value = input_value['id']
                if not input_value or 'id' not in input_value.keys() or not isinstance(input_value['id'], (int, str)):
                    raise exceptions.Formatting.InvalidNotebookIdFormat(input_value)
                final_notebooks.append({'key': 'notebook', 'id': int(input_value['id'])})
            else:
                try:
                    final_notebooks.append({'key': 'notebook', 'id': int(input_value)})
                except (ValueError, TypeError):
                    raise exceptions.Formatting.InvalidNotebookIdFormat(input_value)
        return final_notebooks

    @staticmethod
    def _format_stream_id(alert_id):
        if isinstance(alert_id, str):
            if not re.match(r'^(?:stream-)?\d+$', alert_id):
                raise exceptions.Formatting.InvalidStreamIdFormat(alert_id)
            alert_id = re.sub(r'\D+', '', alert_id)
        return int(alert_id)

    def case_overwrite_attached_notebooks(self, case_id, notebooks):
        notebooks = self._format_notebook_ids(notebooks)
        case_id = self._format_case_id(case_id)
        body = {
            "notebookAttachmentIds": notebooks,
            "notebookAttachedEntityId": {
                "key": "case",
                "id": case_id,
            }
        }
        response = self._http_request(
            url=self.url.notebooks_attach,
            method="PATCH",
            headers={"Content-Type": "application/json"},
            params={"libraryView": "all"},
            body=body
        )
        return response.json()

    def user_groups(self, limit=None, hide_inactive=False):
        limit = limit if limit and isinstance(limit, int) else 99999
        params = {"pageSize": limit, "after": 0}
        body = {"filters": []}
        if hide_inactive:
            body['filters'].append({"hideDeleted": True})
        response = self._http_request(
            url=self.url.user_groups,
            method="POST",
            headers={"Content-Type": "application/json"},
            params=params,
            body=body
        )
        return response.json()

    def users(self, limit=None, hide_inactive=False):
        limit = limit if limit and isinstance(limit, int) else 99999
        params = {"pageSize": limit, "after": 0}
        body = {"filters": []}
        if hide_inactive:
            body['filters'].append({"hideInactive": True})
        response = self._http_request(
            url=self.url.users,
            method="POST",
            headers={"Content-Type": "application/json"},
            params=params,
            body=body
        )
        return response.json()

    def alert_fetch(self, alert_id, return_raw=False, **kwargs):
        alert_id = self._format_alert_id(alert_id)
        url = self.url.alert_fetch.format(alert_id)
        # Send request, but disable immediate testing in order to do specialized testing first
        response = self._http_request(method="GET", url=url, test_response=False, **kwargs)
        if return_raw:
            return response
        if response.status_code == 400 and re.search(r'Alert with id alert-\d+ doesn\'t exist', response.text):
            raise ValueError(f'No alert with ID {alert_id}')
        self.__standard_http_response_tests(response, url)
        return response.json()

    def alerts_search_validate(self, query: str):
        if query:
            # First confirm that the query is valid
            body = {"queryType": "advanced", "query": query}
            response = self._http_request(
                url=self.url.alerts_search_validate,
                method="POST",
                headers={"Content-Type": "application/json"},
                body=body
            )
            response = response.json()
            is_invalid = response['result'].get('error')
            if is_invalid is None:
                raise exceptions.Validation.BaseValidationError('Unexpected response while validating query string.')
            elif is_invalid:
                raise exceptions.Validation.AlertQueryValidationError(response['result'].get('message'))

    def alerts_search_advanced(self, query: str = None, limit: int = None):
        # Sanitize inputs
        limit = int(limit) if limit and int(limit) > 0 else self.DEFAULT_ALERT_RESULT_LIMIT
        query = query.strip() if query and query.strip() else ""
        self.alerts_search_validate(query)

        # Now prep the actual query
        body = {
            "pageNumber": 0,
            "pageSize": limit,
            "sortCol": "id",
            "sortOrder": "desc",
            "query": query
        }
        response = self._http_request(
            url=self.url.alerts_search_advanced,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=body
        )
        return response.json()

    def stream_pause(self, stream_id, **kwargs):
        # Sanitize stream ID
        body = [f"stream-{self._format_stream_id(stream_id)}"]
        response = self._http_request(method="POST", url=self.url.stream_pause, body=body, **kwargs)
        return response.json()

    def stream_resume(self, stream_id, **kwargs):
        # Sanitize stream ID
        body = [f"stream-{self._format_stream_id(stream_id)}"]
        response = self._http_request(method="POST", url=self.url.stream_resume, body=body, **kwargs)
        return response.json()


class LogicHub:
    log: Logger = None
    verify_ssl = True

    def __init__(self, hostname, api_key, verify_ssl=True, cache_seconds=None, **kwargs):
        # If the LogicHubAPI class object has not been given a logger by the time this class is instantiated, set one for it
        LogicHubAPI.log = LogicHubAPI.log or self.log or Logger()

        # If this class has not been given a logger by the time it is instantiated, set it to match the LogicHubAPI class's logger
        self.log = self.log or LogicHubAPI.log

        LogicHubAPI.verify_ssl = self.verify_ssl

        self.kwargs = kwargs
        self.api = LogicHubAPI(hostname=hostname, api_key=api_key, verify_ssl=verify_ssl, cache_seconds=cache_seconds, **kwargs)
        # ToDo Decide if it's best to have this module verify auth automatically or leave this as an optional test
        # _ = self.verify_api_auth()

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

    def action_get_batches_by_stream_id(self, stream_id: int, limit=25, statuses=None, exclude_empty_results=False):
        result = self.api.get_batches_by_stream_id(stream_id, limit=limit, statuses=statuses, exclude_empty_results=exclude_empty_results)
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
