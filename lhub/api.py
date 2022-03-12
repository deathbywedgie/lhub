import atexit
import base64
import json
import os
import re
from collections import namedtuple
from pathlib import Path

import requests
import sys
import time

from . import exceptions
from .log import Logger
from .url import URLs
from .common import helpers

cached_obj = namedtuple('CachedObject', ['time', 'value'])


class LogicHubAPI:
    DEFAULT_ALERT_RESULT_LIMIT = 100
    DEFAULT_CACHE_SECONDS = 300
    USER_AGENT_STRING = "LHUB CLI"
    http_timeout_default = 120
    verify_ssl = True
    log: Logger = None
    last_response_status = None
    last_response_text = None

    __exit_set = False
    __version = None
    __version_info = None
    __case_prefix = None
    __fields = None
    __notebooks = None

    # Variables used only for API token auth
    __api_key = None

    # Variables used only for password auth
    __username = None
    __password = None
    _http_timeout_login = 20
    __credentials = {}
    __session_cookie = None

    def __init__(self, hostname, api_key=None, username=None, password=None, verify_ssl=True, cache_seconds=None, **kwargs):
        # First store key variables and then determine whether they are valid
        self.__api_key = api_key.strip() if api_key else None
        self.__username = username.strip() if username else None
        self.__password = password.strip() if password else None
        assert api_key or (username and password), "Must provide either an API key or a username and password"
        assert not (api_key and password), "Using both an API token and a password is not supported"

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

        if self.__api_key:
            self.auth_type = 'token'
        else:
            self.auth_type = 'password'
            self.__credentials = {"email": self.__username, "password": self.__password}

        self.url = URLs(hostname)
        self.url._version = self.version
        _ = atexit.register(self.close)

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
        if self.__session_cookie:
            headers['Cookie'] = f'PLAY_SESSION={self.__session_cookie}'
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
            result = self.list_notebooks()
            self.notebooks = result["result"]["data"]["data"]
        return self.__notebooks.value

    @notebooks.setter
    def notebooks(self, val):
        self.__notebooks = cached_obj(int(time.time()), val)

    @property
    def notebooks_name_map(self):
        return {notebook['name']: notebook['id']['id'] for notebook in self.notebooks}

    @property
    def session_cookie(self):
        # ToDo Replace this later, but for now include this until I'm sure the update is all ready
        if self.__api_key:
            raise Exception('Session cookie should not be invoked')
        if not self.__session_cookie:
            self.login()
        return self.__session_cookie

    @session_cookie.setter
    def session_cookie(self, value):
        self.__session_cookie = value

    @property
    def cookies(self):
        if not self.__session_cookie:
            return {}
        return {'PLAY_SESSION': self.session_cookie}

    def __standard_http_response_tests(self, response_obj, url):
        # Group all tests for status code 401
        if response_obj.status_code == 401:
            if self.auth_type == 'password':
                raise exceptions.Auth.PasswordAuthFailure
            else:
                if 'Unauthorized for URL' in response_obj.text or 'token is not allowed with this endpoint' in response_obj.text:
                    raise exceptions.Auth.APIAuthNotAuthorized(url)
                else:
                    raise exceptions.Auth.APIAuthFailure(url)

        # Group all tests for status code 400
        elif response_obj.status_code == 400:
            if self.auth_type == 'password':
                if url == self.url.login and 'Username/Password not valid' in self.last_response_text:
                    raise exceptions.Auth.PasswordAuthFailure
            if 'batch' in url and re.search(r'controllers.BatchController.legacyPost.*?For input string', response_obj.text):
                _id = re.search(r'POST /demo/batch-(\d+)', response_obj.text)
                _id = _id.groups()[0] if _id else None
                raise exceptions.BatchNotFound(_id)

        # Group all tests for status code 500
        elif response_obj.status_code == 500:
            if 'Unable to find batch with id' in response_obj.text:
                _id = re.search(r'Unable to find batch with id batch-(\d+)', response_obj.text)
                _id = _id.groups()[0] if _id else None
                raise exceptions.BatchNotFound(_id)

        response_obj.raise_for_status()

    def _http_request(
            self, url, method="GET", params: dict = None, body=None,
            headers: dict = None, timeout=None, test_response: bool = True,
            reauth=True, **kwargs):
        method = method.upper() if method else "GET"
        # Only use reauth/automatic login if password auth is used
        if self.auth_type == 'password':
            # If called before successful login, run login process, but only if reauth was not disabled
            if reauth and not self.__session_cookie:
                self.login(force_new_session=True)
                # Disable re-authentication going forward
                reauth = False

        # Reset last response text
        self.last_response_text = self.last_response_status = None
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
        response = requests.request(method=method, url=url, verify=self.verify_ssl, timeout=timeout, cookies=self.cookies, **kwargs)

        # Only use reauth/automatic login if password auth is used
        if self.auth_type == 'password':
            # if the response fails because the session has ended or the user has logged out, log back in and try once more
            if response.status_code == 401 and reauth and "not logged in" in response.text:
                self.log.debug(f"Session expired; logging in and retrying")
                self.login(force_new_session=True)
                response = requests.request(method=method, url=url, verify=self.verify_ssl, timeout=timeout, cookies=self.cookies, **kwargs)

        # Store last response before testing whether the call was successful
        self.last_response_status = response.status_code
        self.last_response_text = response.text
        if test_response:
            self.__standard_http_response_tests(response, url)
        return response

    def login(self, force_new_session=False):
        if self.auth_type != 'password':
            raise exceptions.LhBaseException('Login process is only used for password auth')
        if force_new_session:
            self.__session_cookie = None

        if self.__session_cookie:
            self.log.debug("Already logged in; login skipped")
            return

        self.log.debug("Logging into LogicHub")
        login_response = self._http_request(url=self.url.login, method="POST", body=self.__credentials, timeout=self._http_timeout_login, reauth=False)
        self.session_cookie = login_response.cookies.get("PLAY_SESSION")
        self.log.debug("Login successful")

    def logout(self):
        if self.auth_type != 'password':
            raise exceptions.LhBaseException('Login process is only used for password auth')
        if not self.session_cookie:
            self.log.debug("Already logged out; logout skipped")
            return

        self.log.debug("Logout requested")
        _response = self._http_request(url=self.url.logout, method="POST", test_response=False, reauth=False, timeout=self._http_timeout_login)
        try:
            _response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            self.log.warn(f"Logout failed with HTTP error: {str(err)}")
        except Exception as err:
            self.log.warn(f"Logout failed with UNKNOWN error: {repr(err)}")
        else:
            self.log.debug(f"Logout successful")
            self.session_cookie = None

    def close(self):
        """Steps to clean up on exit"""
        if self.auth_type == 'password':
            self.log.debug("LogicHubAPI class exiting...")
            self.logout()

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

    def get_batch_results_by_id(self, batch_id: int, limit=1000, offset=0):
        limit = int(limit or 1000)
        offset = int(offset or 0)
        params = {"fields": "*", "pageSize": limit, "after": offset, "cachedOnly": "true"}
        response = self._http_request(url=self.url.batch_results_by_id.format(int(batch_id)), params=params)
        return response.json()

    def get_batches_by_stream_id(self, stream_id, limit=25, offset=0, statuses=None, exclude_empty_results=False):
        if limit == -1:
            limit = 999999999
        params = {
            "pageSize": int(limit or 25),
            "after": int(offset or 0),
        }
        body = {"status": statuses or [], "excludeBatchesWithZeroEvents": exclude_empty_results}
        response = self._http_request(method="POST", url=self.url.stream_batches.format(stream_id), params=params, body=body)
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

    def get_event_types(self, limit=25):
        limit = int(limit or 25)
        if self.version < 70:
            return self.__get_event_types_v1(limit=limit)
        return self.__get_event_types_v2(limit=limit)

    def get_integrations(self):
        response = self._http_request(method="GET", url=self.url.integrations)
        return response.json()

    def get_rule_set_by_name(self, name):
        rule_sets = self.get_rule_sets()
        rule_set = [x for x in rule_sets if x['name'] == name]
        if not rule_set:
            raise exceptions.RuleSetNotFound(f"No rule set found matching name: {name}")
        rule_set = rule_set[0]
        rule_set['rules'] = self.get_rules_for_rule_set(rule_set['id'])
        return rule_set

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

    # ToDo STILL DOES NOT WORK WITH API AUTH AS OF M91
    def get_rules_for_rule_set(self, rule_set):
        rule_set = helpers.sanitize_input_rule_set_id(rule_set)
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

    def get_stream_by_id(self, stream_id: int):
        headers = {"Accept": "application/json"}
        # ToDo Revisit this. I better approach might be:
        # try:
        #     response = self._http_request(url=self.url.stream_by_id.format(stream_id), headers=headers)
        #     return response.json()
        # except requests.exceptions.HTTPError:
        #     if self.last_response_status == 400 and 'Cannot find entity for id StreamId' in self.last_response_text:
        #         raise exceptions.StreamNotFound(stream_id)
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

    def get_version_info(self):
        self.log.debug("Fetching LogicHub version")
        try:
            response = self._http_request(
                url=self.url.version,
                reauth=False,
                timeout=self.http_timeout_default)
            response_dict = response.json()
        except (KeyError, ValueError, TypeError, IndexError):
            raise exceptions.LhBaseException("LogicHub version could not be established")
        else:
            # Update version information any time this api call is run successfully
            self.version_info = response_dict
            self.version = float(re.match("m(.*)", self.version_info["version"]).group(1))
        return response_dict

    def get_workflow_by_id(self, workflow_id: int):
        assert isinstance(workflow_id, int), "Workflow ID must be an integer"
        response = self._http_request(method="GET", url=self.url.case_status_workflow_by_id.format(workflow_id))
        return response.json()

    def get_workflows(self):
        response = self._http_request(method="GET", url=self.url.case_status_list_workflows)
        return response.json()

    # ToDo STILL DOES NOT WORK WITH API AUTH AS OF M91
    # ToDo Create an action method for this, and update the beta integration action to use it
    def add_scoring_rule(self, rule_set, field_mappings, score: float or str):
        rule_set = helpers.sanitize_input_rule_set_id(rule_set)
        field_mappings = helpers.sanitize_input_rule_field_mappings(field_mappings)
        score = helpers.sanitize_input_rule_score(score)
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

    def export_playbook(self, playbook_id, test_response=True):
        response = self._http_request(url=self.url.flow_export.format(playbook_id), test_response=test_response)
        return response.json()

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

    def list_playbooks(self, limit=None):
        limit = int(limit or 99999)
        body = {"filters": [], "offset": 0, "pageSize": limit, "sortColumn": "name", "sortOrder": "ASC"}
        response = self._http_request(
            url=self.url.playbooks_list,
            method="POST",
            params={"pageSize": limit},
            body=body
        )
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

    def list_dashboards_with_widgets(self):
        response = self._http_request(url=self.url.dashboards_and_widgets)
        return response.json()

    def list_fields(self, params: dict = None, **kwargs):
        params = params or {"systemFields": "true", "pageSize": 9999, "after": 0}
        response = self._http_request(method="GET", url=self.url.fields, params=params, **kwargs)
        self.fields = response.json()
        return response.json()

    def list_ml_models(self):
        response = self._http_request(
            method="GET",
            url=self.url.ml_models,
            headers={"Content-Type": "application/json"},
        )
        return response.json()

    def list_modules(self):
        response = self._http_request(
            method="GET",
            url=self.url.modules,
            headers={"Content-Type": "application/json"}
        )
        return response.json()

    def list_notebooks(self, limit=None, search_string=None):
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
        self.notebooks = response["result"]["data"]["data"] = helpers.sort_notebook_objects_by_id(response["result"]["data"]["data"])
        return response

    def list_streams(self, search_text: str = None, filters: list = None, limit: int = 25, offset: int = 0):
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
    #         i = helpers.format_alert_id(i)
    #         if i:
    #             updated_alerts.append(i)
    #     alert_ids = updated_alerts
    #
    #     case_id = helpers.format_case_id_with_prefix(case_id, self.case_prefix)
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

    def case_list_attached_notebooks(self, case_id, results_only=False):
        case_id = helpers.format_case_id_with_prefix(case_id, self.case_prefix)
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
        results = response['result'] = helpers.sort_notebook_objects_by_id(response['result'])
        if results_only:
            for n in range(len(results)):
                results[n]['id']['id'] = int(results[n]['id']['id'])
            return results
        return response

    def case_overwrite_attached_notebooks(self, case_id, notebooks):
        notebooks = helpers.format_notebook_ids(notebooks)
        case_id = helpers.format_case_id_with_prefix(case_id, self.case_prefix)
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
        alert_id = helpers.format_alert_id(alert_id)
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
        body = [f"stream-{helpers.format_stream_id(stream_id)}"]
        response = self._http_request(method="POST", url=self.url.stream_pause, body=body, **kwargs)
        return response.json()

    def stream_resume(self, stream_id, **kwargs):
        # Sanitize stream ID
        body = [f"stream-{helpers.format_stream_id(stream_id)}"]
        response = self._http_request(method="POST", url=self.url.stream_resume, body=body, **kwargs)
        return response.json()
