import atexit
import json
import re
from collections import namedtuple

from requests import request, models
from requests.exceptions import HTTPError
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
import sys
import time

from . import exceptions
from .log import prep_generic_logger
from .url import URLs
from .common import helpers
from logging import getLogger, RootLogger
from typing import List

log = getLogger(__name__)
cached_obj = namedtuple('CachedObject', ['time', 'value'])


class LogicHubAPI:
    DEFAULT_ALERT_RESULT_LIMIT = 100
    DEFAULT_CASE_RESULT_LIMIT = 25
    DEFAULT_CACHE_SECONDS = 300
    USER_AGENT_STRING = "LHUB CLI"
    http_timeout_default = 120
    verify_ssl = True
    last_response_status = None
    last_response_text = None

    __exit_set = False
    __version = None
    __version_info = None
    __case_prefix = None
    __fields = None
    __notebooks = None
    __hostname = None
    __user_id = None
    __user_role = None

    # Variables used only for API token auth
    __api_key = None

    # Variables used only for password auth
    __username = None
    __password = None
    _http_timeout_login = 20
    __credentials = {}
    __session_cookie = None

    def __init__(self, hostname, api_key=None, username=None, password=None,
                 verify_ssl=True, cache_seconds=None, default_timeout=None,
                 logger: RootLogger = None, log_level=None, **kwargs):
        global log
        if logger:
            log = logger
        else:
            prep_generic_logger(level=log_level)
        if not hostname:
            raise exceptions.validation.InputValidationError(input_var=None, action_description="instantiation", message="No hostname provided")
        if not api_key and not (username and password):
            raise exceptions.validation.InputValidationError(input_var=None, action_description="instantiation", message="Must provide either an API key or a username and password")
        if api_key and password:
            raise exceptions.validation.InputValidationError(input_var=None, action_description="instantiation", message="Using both an API token and a password is not supported")
        self.__hostname = hostname
        self.__api_key = api_key or None
        self.__username = username or None
        self.__password = password or None

        self.cache_seconds = int(cache_seconds or LogicHubAPI.DEFAULT_CACHE_SECONDS)
        if self.cache_seconds is None or self.cache_seconds < 0:
            self.cache_seconds = 0

        if default_timeout:
            self.http_timeout_default = int(default_timeout)
        self._http_timeout_login = min(self._http_timeout_login, self.http_timeout_default)
        self.kwargs = kwargs

        if isinstance(verify_ssl, bool):
            self.verify_ssl = verify_ssl
        if not self.verify_ssl:
            # Disable certificate warnings
            log.debug("Disabling SSL warnings...")
            disable_warnings(InsecureRequestWarning)

        if self.__api_key:
            self.auth_type = 'token'
        else:
            self.auth_type = 'password'
            self.__credentials = {"email": self.__username, "password": self.__password}

        __init_version = self.kwargs.pop('init_version', None)
        self.url = URLs(hostname, init_version=__init_version)
        log.debug(f"Starting session for server: {self.session_hostname}")
        self.__set_version(__init_version)
        self.formatted = FormattedObjects(api=self)

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

    def __set_version_info(self, value):
        self.__version_info = cached_obj(int(time.time()), value)

    @property
    def fields(self):
        if not self.__get_cached_object(self.__fields):
            _ = self.list_fields()
        return self.__fields.value

    @fields.setter
    def fields(self, value):
        self.__fields = cached_obj(int(time.time()), value)

    @property
    def version(self):
        if not self.__get_cached_object(self.__version):
            _ = self.get_version_info()
        return self.__version.value

    @property
    def major_version(self):
        return int(float(self.version))

    @property
    def minor_version(self):
        return int(re.sub(r'^.*?(\d+)$', '$1', self.version))

    def __set_version(self, value):
        if value is None:
            _ = self.get_version_info()
            return
        self.__version = cached_obj(int(time.time()), helpers.format_version(value))
        log.debug(f"LogicHub version: {self.version}")
        # Update the version attribute in self.url for use in other calls since the URLs class does not make any such calls on its own
        self.url._current_version = self.version

    @property
    def case_prefix(self):
        if not self.__get_cached_object(self.__case_prefix):
            _ = self.cases_get_prefix()
        return self.__case_prefix.value

    @property
    def session_hostname(self):
        return self.__hostname

    @property
    def session_username(self):
        if not self.__username:
            _ = self.me()
        return self.__username

    @property
    def session_user_id(self):
        if not self.__user_id:
            _ = self.me()
        return self.__user_id

    @property
    def session_user_role(self):
        if not self.__user_role:
            _ = self.me()
        return self.__user_role

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
        # This should only ever come up w/ password auth, so if this has been invoked when there is an API key then throw an exception
        if self.__api_key:
            raise exceptions.LhBaseException('Session cookie should not be invoked')
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

    def __standard_http_response_tests(self, response_obj: models.Response, url: str, input_var=None):
        # If the response is okay, return successfully right away
        try:
            response_obj.raise_for_status()
            return
        except HTTPError as e:
            caught_exception = e

        try:
            __response_json = response_obj.json()
        except json.decoder.JSONDecodeError:
            __response_json = {}

        __status_code = response_obj.status_code
        __errors = __response_json.get("errors", [])
        __primary_error_type = __errors[0].get("errorType") if __errors else None
        exception_inputs = {
            "input_var": input_var,
            "url": url,
            "last_response_status": __status_code,
            "last_response_text": response_obj.text,
        }

        # Group all tests for status code 401
        if __status_code == 401:
            if self.auth_type == 'password':
                raise exceptions.auth.PasswordAuthFailure(**exception_inputs)
            else:
                if 'Unauthorized for URL' in response_obj.text or 'token is not allowed with this endpoint' in response_obj.text:
                    raise exceptions.auth.APIAuthNotAuthorized(url)
                else:
                    raise exceptions.auth.APIAuthFailure(url)

        # Group all tests for status code 400
        elif __status_code == 400:
            if self.auth_type == 'password':
                if url == self.url.login and 'Username/Password not valid' in self.last_response_text:
                    raise exceptions.auth.PasswordAuthFailure
            if 'batch' in url and re.search(r'controllers.BatchController.legacyPost.*?For input string', response_obj.text):
                _id = re.search(r'POST /demo/batch-(\d+)', response_obj.text)
                _id = _id.groups()[0] if _id else None
                raise exceptions.app.BatchNotFound(_id)
            if __primary_error_type == "AlreadyPresentException":
                if url == self.url.user_create:
                    raise exceptions.app.UserAlreadyExists(user=input_var)
                if url == self.url.user_group_create:
                    raise exceptions.app.UserGroupAlreadyExists(input_var=input_var)

        # Group all tests for status code 500
        elif __status_code == 500:
            if 'Unable to find batch with id' in response_obj.text:
                _id = re.search(r'Unable to find batch with id batch-(\d+)', response_obj.text)
                _id = _id.groups()[0] if _id else None
                raise exceptions.app.BatchNotFound(_id)

        raise caught_exception

    def _http_request(
            self, url, method="GET", params: dict = None, body=None,
            headers: dict = None, timeout=None, test_response: bool = True,
            reauth=True, input_var=None, **kwargs):
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
        response = request(method=method, url=url, verify=self.verify_ssl, timeout=timeout, cookies=self.cookies, **kwargs)

        # Only use reauth/automatic login if password auth is used
        if self.auth_type == 'password':
            # if the response fails because the session has ended or the user has logged out, log back in and try once more
            if response.status_code == 401 and reauth and "not logged in" in response.text:
                log.debug(f"Session expired; logging in and retrying")
                self.login(force_new_session=True)
                response = request(method=method, url=url, verify=self.verify_ssl, timeout=timeout, cookies=self.cookies, **kwargs)

        # Store last response before testing whether the call was successful
        self.last_url = url
        self.last_response_status = response.status_code
        self.last_response_text = response.text
        if test_response:
            self.__standard_http_response_tests(response, url, input_var=input_var)
        return response

    def login(self, force_new_session=False):
        if self.auth_type != 'password':
            raise exceptions.LhBaseException('Login process is only used for password auth')
        if force_new_session:
            self.__session_cookie = None

        if self.__session_cookie:
            log.debug("Already logged in; login skipped")
            return

        log.debug("Logging into LogicHub")
        login_response = self._http_request(url=self.url.login, method="POST", body=self.__credentials, timeout=self._http_timeout_login, reauth=False, input_var=self.__username)
        self.session_cookie = login_response.cookies.get("PLAY_SESSION")
        log.debug("Login successful")
        _ = atexit.register(self.close)

    def logout(self):
        log.debug(f"Logout requested [{self.session_hostname}]")
        if self.auth_type != 'password':
            raise exceptions.LhBaseException('Login process is only used for password auth')
        if not self.session_cookie:
            log.debug("Already logged out; logout skipped")
            return

        log.debug("Issuing logout command")
        _response = self._http_request(url=self.url.logout, method="POST", test_response=False, reauth=False, timeout=self._http_timeout_login, input_var=self.__username)
        try:
            _response.raise_for_status()
        except HTTPError as err:
            log.warning(f"Logout failed with HTTP error: {str(err)}")
        except Exception as err:
            log.warning(f"Logout failed with UNKNOWN error: {repr(err)}")
        else:
            log.debug(f"Logout successful")
            self.session_cookie = None

    def close(self):
        """Steps to clean up on exit"""
        if self.auth_type == 'password':
            log.debug("LogicHubAPI class exiting...")
            self.logout()

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
        """

        :param batch_id:
        :param limit: None by default, although the LogicHub UI defaults to 25
        :param offset: Used for pagination if you want to pull in chunks, this sets the page number to pull
        :return:
        """
        limit = int(limit or 1000)
        offset = int(offset or 0)
        params = {"fields": "*", "pageSize": limit, "after": offset, "cachedOnly": "true"}
        log.debug("Fetching batch results")
        response = self._http_request(url=self.url.batch_results_by_id.format(int(batch_id)), params=params, input_var=batch_id)
        return response.json()

    def get_batches_by_stream_id(self, stream_id, limit=None, offset=0, statuses=None, exclude_empty_results=False):
        """

        :param stream_id:
        :param limit: None by default, although the LogicHub UI defaults to 25
        :param offset: Used for pagination if you want to pull in chunks, this sets the page number to pull
        :param statuses:
        :param exclude_empty_results:
        :return:
        """
        limit = int(limit if limit and limit > 0 else 999999999)
        params = {
            "pageSize": limit,
            "after": int(offset or 0),
        }
        body = {"status": statuses or [], "excludeBatchesWithZeroEvents": exclude_empty_results}
        log.debug(f"Fetching batches for stream: {stream_id}")
        response = self._http_request(method="POST", url=self.url.stream_batches.format(stream_id), params=params, body=body, input_var=stream_id)
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
        log.debug("Fetching connection status")
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
        log.debug("Fetching custom list data")
        response = self._http_request(
            method=method,
            url=url,
            params={"offset": offset, "limit": limit},
            body=payload,
            headers={'Content-Type': 'application/json'},
            input_var=list_id
        )
        results = response.json()
        try:
            results = results["result"]
        except Exception:
            raise exceptions.app.UnexpectedOutput("API response does not match the expected schema for listing custom lists")
        return results

    # ToDo Token auth not supported as of 2022-05-05 (m94)
    def get_dashboard(self, dashboard_id):
        log.debug("Fetching dashboard data")
        response = self._http_request(url=self.url.dashboard.format(dashboard_id), input_var=dashboard_id)
        return response.json()

    # ToDo Token auth not supported as of 2022-05-05 (m94)
    def get_dashboard_data(self, dashboard_id):
        log.debug("Fetching dashboard data")
        response = self._http_request(url=self.url.dashboard_data.format(dashboard_id), input_var=dashboard_id)
        return response.json()

    # ToDo Token auth not supported as of 2022-05-05 (m94)
    def get_widget_data(self, dashboard_id, widget_id):
        log.debug("Fetching dashboard data")
        response = self._http_request(url=self.url.widget_data.format(dashboard_id=dashboard_id, widget_id=widget_id), input_var=widget_id)
        return response.json()

    # ToDo STILL DOES NOT WORK WITH API AUTH AS OF M91
    def get_rule_set_by_name(self, name):
        rule_sets = self.list_rule_sets()
        rule_set = [x for x in rule_sets if x['name'] == name]
        if not rule_set:
            raise exceptions.app.RuleSetNotFound(input_var=name)
        rule_set = rule_set[0]
        rule_set['rules'] = self.get_rules_for_rule_set(rule_set['id'])
        return rule_set

    # ToDo STILL DOES NOT WORK WITH API AUTH AS OF M91
    def get_rules_for_rule_set(self, rule_set):
        params = {
            "fields": "name,isPublic,rules[filter,values*1000,score]*1000",
        }
        log.debug("Fetching rules")
        response = self._http_request(url=self.url.rule_set.format(helpers.format_rule_set_id(rule_set)), params=params, input_var=rule_set)
        results = response.json()
        try:
            results = results["result"]["rules"]["data"]
        except Exception:
            raise exceptions.app.UnexpectedOutput("API response does not match the expected schema for listing rules of a rule set")
        return results

    def get_stream_by_id(self, stream_id: int):
        headers = {"Accept": "application/json"}
        log.debug("Fetching stream")
        response = self._http_request(url=self.url.stream_by_id.format(stream_id), headers=headers, test_response=False, input_var=stream_id)
        if response.status_code == 400 and 'Cannot find entity for id StreamId' in response.text:
            raise exceptions.app.StreamNotFound(stream_id)
        else:
            response.raise_for_status()
        return response.json()

    def get_version_info(self):
        log.debug("Fetching LogicHub version info")
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
            self.__set_version_info(response_dict)
            self.__set_version(self.version_info)
        return response_dict

    def get_workflow_by_id(self, workflow_id: int):
        assert isinstance(workflow_id, int), "Workflow ID must be an integer"
        log.debug("Fetching workflow")
        response = self._http_request(method="GET", url=self.url.case_status_workflow_by_id.format(workflow_id), input_var=workflow_id)
        return response.json()

    # ToDo STILL DOES NOT WORK WITH API AUTH AS OF M91
    # ToDo Create an action method for this, and update the beta integration action to use it
    def add_scoring_rule(self, rule_set, field_mappings, score: float or str):
        rule_set = helpers.format_rule_set_id(rule_set)
        field_mappings = helpers.sanitize_input_rule_field_mappings(field_mappings)
        score = helpers.format_rule_score(score)
        headers = {"Content-Type": "application/json"}
        body = {
            "method": "addRule",
            "parameters": {
                "values": [field_mappings],
                "score": score
            }
        }
        log.debug("Issuing new scoring rule")
        response = self._http_request(url=self.url.rule_set.format(rule_set), method="POST", body=body, headers=headers, input_var=rule_set)
        results = response.json()
        try:
            results = results["result"]
        except Exception:
            raise exceptions.app.UnexpectedOutput("API response does not match the expected schema for adding a scoring rule")
        return results

    def export_playbook(self, playbook_id, test_response=True):
        log.debug(f"Exporting playbook {playbook_id}")
        response = self._http_request(url=self.url.flow_export.format(playbook_id), test_response=test_response, input_var=playbook_id)
        return response.json()

    def execute_command(self, command_payload, limit=None):
        """

        :param command_payload:
        :param limit: None by default, although the LogicHub UI defaults to 25
        :return:
        """
        limit = int(limit if limit and limit > 0 else 999999999)
        log.debug("Executing LogicHub command")
        response = self._http_request(
            url=self.url.command_execute,
            method="POST",
            body=command_payload,
            test_response=False,
            params={"pageSize": limit}
        )
        try:
            result_dict = response.json()
        except json.decoder.JSONDecodeError:
            msg = f"Failed to load API response as JSON. Status code: {response.status_code} Response text: {response.text}"
            log.fatal(msg)
            raise exceptions.app.UnexpectedOutput(msg)

        errors = result_dict.pop("errors", [])
        if errors:
            log.warning(f"Request was successful, but command failed with errors")
            log.debug(f"Full error list: {json.dumps(errors)}")
            log.debug(f"Other error response data: {json.dumps(result_dict)}")
            try:
                log.warning(f"Direct link to command: {self.url.command.format(errors[0]['details']['flowId'])}")
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
                    log.debug(f"Command error details: {error_details}")

                if error:
                    # [DEBUG] [0x10f00cef0] Additional error fields: {"cause": "lql.LqlValidator$OperatorException: [Error Executing Operator: select]"}
                    log.debug(f"Additional error fields: {json.dumps(error)}")

                # [FATAL] [0x11dc8b400] Command returned error (SparkRuntimeException): [Execution Error] Executing node final_output failed.
                # [Error Executing Operator: select]. <<(lhub_file_id,None)>> does not exist in the table.
                log.error(f"Command returned error ({error_type}): {error_msg}")
            sys.exit(1)

        try:
            response.raise_for_status()
        except HTTPError:
            message = f"Request failed with status code {response.status_code}\n\nText:\n\n"
            try:
                message += json.dumps(response.json(), indent=2)
            except (json.decoder.JSONDecodeError, ValueError, TypeError):
                message += response.text
            log.fatal(message)
        return response.json()

    def list_baselines(self, limit=None, offset=0, filters=None):
        """
        List all Baselines

        :param limit: None by default, although the LogicHub UI defaults to 25
        :param offset: Used for pagination if you want to pull in chunks, this sets the page number to pull
        :param filters: Optional: Advanced search filters (list of dicts)
        :return:
        """
        limit = int(limit if limit and limit > 0 else 999999999)
        params = {"libraryView": "all"}
        body = {"filters": filters or [], "offset": offset or 0, "pageSize": limit, "sortColumn": "name", "sortOrder": "ASC"}
        log.debug("Fetching baselines")
        response = self._http_request(method="POST", url=self.url.baselines, params=params, body=body)
        return response.json()

    def list_case_types(self, limit=None, after=0, exclude_deprecated: bool = True):
        """
        List all case types

        :param limit: None by default, although the LogicHub UI defaults to 25
        :param after: Used for pagination if you want to pull in chunks, this sets the result number to start after
        :param exclude_deprecated: Exclude deprecated case types (default: True)
        :return:
        """
        limit = int(limit if limit and limit > 0 else 999999999)
        params = {
            "pageSize": limit,
            "excludeDeprecated": str(exclude_deprecated or True).lower(),
            "after": after or 0,
        }
        log.debug("Fetching case types")
        response = self._http_request(url=self.url.case_types, params=params)
        return response.json()

    def search_entities(self, entity_type: str, query: str = None, limit: int = None, offset: int = 0):
        """
        Search content entities

        :param entity_type: type of entity to search (such as "eventTypes" or "connections")
        :param query: Search query (default: all entities of the given type)
        :param limit: Result limit (default: None)
        :param offset: Used for pagination if you want to pull in chunks, this sets the page number to pull
        :return:
        """
        body = {
            "query": query or "*",
            "pageSize": int(limit if limit and limit > 0 else 999999999),
            "page": offset
        }
        log.debug(f"Searching entities of type: {entity_type}")
        response = self._http_request(method="POST", url=self.url.entities_search.format(entity_type), body=body)
        return response.json()

    def list_commands(self, limit=None, offset=0, filters=None):
        """
        List all Commands

        :param limit: None by default, although the LogicHub UI defaults to 25
        :param offset: Used for pagination if you want to pull in chunks, this sets the page number to pull
        :param filters: Optional: Advanced search filters (list of dicts)
        :return:
        """
        limit = int(limit if limit and limit > 0 else 999999999)
        params = {"libraryView": "all"}
        body = {"filters": filters or [], "offset": offset or 0, "pageSize": limit, "sortColumn": "name", "sortOrder": "ASC"}
        log.debug("Fetching commands")
        response = self._http_request(method="POST", url=self.url.commands, params=params, body=body)
        return response.json()

    def list_connections(self, filters=None, limit=None, offset=0):
        """
        List all connections

        :param filters: Optional: Advanced search filters (list of dicts)
        :param limit: None by default, although the LogicHub UI defaults to 25
        :param offset: Used for pagination if you want to pull in chunks, this sets the page number to pull
        :return:
        """
        limit = int(limit if limit and int(limit) and limit >= 1 else 99999)
        params = {"libraryView": "all"}
        headers = {"Content-Type": "application/json"}
        body = {"filters": filters or [], "offset": offset, "pageSize": limit, "sortColumn": "name", "sortOrder": "ASC"}
        log.debug("Fetching connections")
        response = self._http_request(method="POST", url=self.url.connections, headers=headers, params=params, body=body)
        return response.json()

    def list_custom_lists(self, search_text: str = None, filters: list = None, limit: int = None, offset: int = None, verify_results=True):
        """

        :param search_text: Optional: Part or all of the custom list name to filter by
        :param filters: Optional: Advanced search, e.g. [{"searchText":"<case name>"}]
        :param limit: None by default, although the LogicHub UI defaults to 25
        :param offset: Used for pagination if you want to pull in chunks, this sets the page number to pull
        :param verify_results: Optional: set to false to return response JSON without verifying that the format is as expected
        :return:
        """
        limit = int(limit if limit and limit > 0 else 999999999)
        offset = int(offset or 0)
        filters = filters or []
        if search_text:
            filters.append({"searchText": search_text})

        log.debug("Fetching custom lists")
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
                raise exceptions.app.UnexpectedOutput("API response does not match the expected schema for listing custom lists")
        return results

    # ToDo Token auth not supported as of 2022-03-09 (m92)
    def list_dashboards(self):
        log.debug("Fetching dashboards")
        response = self._http_request(url=self.url.dashboards)
        return response.json()

    def list_dashboards_with_widgets(self):
        log.debug("Fetching dashboards with widgets")
        response = self._http_request(url=self.url.dashboards_and_widgets)
        return response.json()

    def __list_event_types_v1(self, limit=None):
        """

        :param limit: None by default, although the LogicHub UI defaults to 25
        :return:
        """
        # Not sure when this one stopped working, but it worked somewhere in at least m66 and didn't work any more in m70
        limit = int(limit if limit and limit > 0 else 999999999)
        params = {"limit": limit}
        log.debug("Fetching event types")
        response = self._http_request(url=self.url.event_types, params=params)
        results = response.json()
        if results.get("result"):
            results = results["result"]
        if results.get("data"):
            results = results["data"]
        return results

    def __list_event_types_v2(self, limit=None, offset=0):
        """

        :param limit: None by default, although the LogicHub UI defaults to 25
        :param offset: Used for pagination if you want to pull in chunks, this sets the page number to pull
        :return:
        """
        limit = int(limit if limit and limit > 0 else 999999999)
        params = {"libraryView": "all"}
        # Confirm the right term for "name" as the sort column and change this sort order
        body = {"filters": [], "pageSize": limit, "offset": offset or 0, "sortColumn": "lastUpdated", "sortOrder": "DESC"}
        log.debug("Fetching event types")
        response = self._http_request(method="POST", url=self.url.event_types, params=params, body=body)
        results = response.json()
        if results.get("result"):
            results = results["result"]
        while isinstance(results, dict) and results.get('data') is not None:
            results = results["data"]
        return results

    def list_event_types(self, limit=None):
        """

        :param limit: None by default, although the LogicHub UI defaults to 25
        :return:
        """
        limit = int(limit if limit and limit > 0 else 999999999)
        # ToDo Remove this old version when it's safe to assume no one still uses m70
        if self.major_version < 70:
            return self.__list_event_types_v1(limit=limit)
        return self.__list_event_types_v2(limit=limit)

    def list_fields(self, params: dict = None, **kwargs):
        params = params or {"systemFields": "true", "pageSize": 9999, "after": 0}
        log.debug("Fetching fields")
        response = self._http_request(method="GET", url=self.url.fields, params=params, **kwargs)
        self.fields = response.json()
        return response.json()

    def list_integrations(self):
        log.debug("Fetching integrations")
        response = self._http_request(method="GET", url=self.url.integrations)
        return response.json()

    def list_ml_models(self):
        log.debug("Fetching ML models")
        response = self._http_request(
            method="GET",
            url=self.url.ml_models,
            headers={"Content-Type": "application/json"},
        )
        return response.json()

    def list_modules(self):
        log.debug("Fetching modules")
        response = self._http_request(
            method="GET",
            url=self.url.modules,
            headers={"Content-Type": "application/json"}
        )
        return response.json()

    def list_notebooks(self, limit=None, offset=0, search_string=None):
        """
        List all Notebooks

        :param limit: None by default, although the LogicHub UI defaults to 25
        :param offset: Used for pagination if you want to pull in chunks, this sets the page number to pull
        :param search_string:
        :return:
        """
        limit = limit if limit and isinstance(limit, int) else 99999
        body = {
            "filters": [],
            "offset": offset or 0,
            "pageSize": limit,
            "sortColumn": "name",
            "sortOrder": "ASC",
        }
        if search_string:
            body['filters'] = [{"searchText": search_string}]
        log.debug("Fetching notebooks")
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

    def list_playbooks(self, limit=None, offset=0):
        """
        List all Playbooks

        :param limit: None by default, although the LogicHub UI defaults to 25
        :param offset: Used for pagination if you want to pull in chunks, this sets the page number to pull
        :return:
        """
        limit = int(limit if limit and limit > 0 else 999999999)
        body = {"filters": [], "offset": offset or 0, "pageSize": limit, "sortColumn": "name", "sortOrder": "ASC"}
        log.debug("Fetching playbooks")
        response = self._http_request(
            url=self.url.playbooks_list,
            method="POST",
            params={"pageSize": limit},
            body=body
        )
        return response.json()

    def get_playbook_versions(self, playbook_id, limit=25, offset=0):
        limit = int(limit if limit is not None and limit > 0 else 25)
        offset = offset or 0
        log.debug(f"Fetching up to {limit} versions for playbook {playbook_id}")
        response = self._http_request(self.url.playbook_versions.format(playbook_id), params={"offset": offset, "limit": limit})
        return response.json()

    # ToDo STILL DOES NOT WORK WITH API AUTH AS OF M91
    def list_rule_sets(self, limit=None):
        """

        :param limit: None by default, although the LogicHub UI defaults to 25
        :return:
        """
        limit = int(limit if limit and limit > 0 else 999999999)
        params = {
            "fields": "name,isPublic",
            "pageSize": limit,
        }
        log.debug("Fetching rule sets")
        response = self._http_request(url=self.url.rule_sets, params=params)
        results = response.json()
        try:
            results = results["result"]["data"]
        except Exception:
            raise exceptions.app.UnexpectedOutput("API response does not match the expected schema for listing rule sets")
        return results

    def list_saml_configs(self):
        log.debug("Fetching SSO configurations")
        response = self._http_request(url=self.url.saml_configs)
        return response.json()

    def list_stream_states(self, stream_ids: List[int]):
        new_stream_id_list = []
        for s in stream_ids:
            new_stream_id_list.append(f'stream-{s}')
        body = {"streams": new_stream_id_list}
        log.debug("Fetching stream states")
        response = self._http_request(method="POST", url=self.url.stream_states, body=body, input_var=stream_ids)
        return response.json()

    def list_streams(self, search_text: str = None, filters: list = None, limit: int = None, offset: int = 0):
        """
        List all streams

        :param search_text:
        :param filters:
        :param limit: None by default, although the LogicHub UI defaults to 25
        :param offset: Used for pagination if you want to pull in chunks, this sets the page number to pull
        :return:
        """
        limit = int(limit if limit and limit > 0 else 999999999)
        params = {"libraryView": "all"}
        headers = {"Content-Type": "application/json"}

        filters = filters or []
        if search_text:
            filters.append({"searchText": search_text})

        body_dict = {
            "filters": filters,
            "offset": offset or 0,
            "pageSize": limit,
            "sortColumn": "name",
            "sortOrder": "ASC"
        }

        log.debug("Fetching streams")
        response = self._http_request(method="POST", url=self.url.streams, body=body_dict, headers=headers, params=params)
        return response.json()

    def list_user_groups(self, limit=None, hide_inactive=True):
        limit = limit if limit and isinstance(limit, int) else 99999
        params = {"pageSize": limit, "after": 0}
        body = {"filters": []}
        if hide_inactive:
            body['filters'].append({"hideDeleted": True})
        log.debug("Fetching user groups")
        response = self._http_request(
            url=self.url.user_groups,
            method="POST",
            headers={"Content-Type": "application/json"},
            params=params,
            body=body
        )
        return response.json()

    def __list_users_v1_up_to_m95(self, limit=None, hide_inactive=True):
        limit = limit if limit and isinstance(limit, int) else 99999
        params = {"pageSize": limit, "after": 0}
        body = {"filters": []}
        if hide_inactive:
            body['filters'].append({"hideInactive": True})
        log.debug("Fetching users")
        response = self._http_request(
            url=self.url.users,
            method="POST",
            headers={"Content-Type": "application/json"},
            params=params,
            body=body
        )
        return response.json()

    def __list_users_v2_from_m96(self, limit=None, **kwargs):
        limit = limit if limit and isinstance(limit, int) else 99999
        params = {"pageSize": limit, "after": 0}
        body = {"filters": []}
        if kwargs:
            body["filters"].append(kwargs)
        log.debug("Fetching users")
        response = self._http_request(
            url=self.url.users,
            method="POST",
            headers={"Content-Type": "application/json"},
            params=params,
            body=body
        )
        return response.json()

    def list_users(self, limit=None, **kwargs):
        if self.major_version > 95 and "hide_inactive" in kwargs:
            raise DeprecationWarning("The \"hideInactive\" filter is no longer valid since LogicHub version m96")

        if self.major_version <= 95:
            func = self.__list_users_v1_up_to_m95
        else:
            func = self.__list_users_v2_from_m96
        return func(limit=limit, **kwargs)

    def list_workflows(self):
        log.debug("Fetching workflows")
        response = self._http_request(method="GET", url=self.url.case_status_list_workflows)
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
        log.debug("Issuing command to reprocess batch")
        response = self._http_request(method="POST", url=self.url.batch_reprocess.format(batch_id), headers=headers, body=body, input_var=batch_id)
        return response.json()

    # introduced somewhere between m70 and m80
    def me(self):
        log.debug("Fetching current user info")
        response = self._http_request(method="GET", url=self.url.me, timeout=30)
        result = response.json()
        if not all((
            result.get('result'),
            result['result']['id'],
            result['result']['username'],
            result['result']['role'],
            result['result']['preferences']
        )):
            raise exceptions.validation.ResponseValidationError(input_var=response, message="API response does not match the expected schema for user profile and preferences")

        self.__user_role = result['result']['role']
        if result['result']:
            new_id = result['result']['id']
            if isinstance(new_id, str):
                new_id = int(re.sub(r'\D+', '', new_id))
            if new_id != self.__user_id:
                self.__user_id = new_id
            # Username will only exist already if password auth is used. In case of API token auth, capture and record the username.
            if self.__username != result['result']['username']:
                self.__username = result['result']['username']
                log.debug(f"Current user updated to {self.__username} [ID: {self.__user_id}, role: {self.__user_role}]")
        return result

    def update_user(self, user_id, change_note=None, **user_kwargs):
        if not user_kwargs:
            raise exceptions.validation.InputValidationError("User update requested, but no changes provided")
        log.debug("Patching user" + (f" ({change_note})" if change_note else ""))
        response = self._http_request(method="PATCH", url=self.url.user.format(user_id), body=user_kwargs, input_var=user_id)
        return response.json()

    def update_current_user_preferences(self, preferences):
        return self.update_user(user_id=self.session_user_id, change_note="updating preferences", preferences=preferences)

    def case_prefix_refresh(self):
        _ = self.cases_get_prefix()
        return self.case_prefix

    # ToDo Revisit eventually. Aborted on 2022-02-22 because it turns out this
    #  can be set w/ the case management integration as a custom field, but
    #  there is still value in finishing this.
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
    #     field_id = self.formatted.system_field_lh_linked_alerts.get('id')
    #     body = {"fields": [{"id": field_id, "value": alert_ids}]}
    #     log.debug("Linking alert to case")
    #     response = self._http_request(
    #         method="PATCH",
    #         url=self.url.case_update_linked_alerts.format(case_id=case_id),
    #         headers={"Content-Type": "application/json"},
    #         input_var=case_id,
    #     )
    #     output = response.json()

    def case_update(self, case_id: str, **kwargs):
        if not kwargs:
            raise exceptions.validation.InputValidationError("No changes provided for updating case", input_var=case_id, action_description="case update")
        log.debug("Updating case")
        response = self._http_request(
            method="PATCH",
            url=self.url.case.format(case_id=case_id),
            headers={"Content-Type": "application/json"},
            body=kwargs
        )
        return response.json()

    def cases_get_prefix(self):
        log.debug("Fetching case prefix")
        response = self._http_request(
            url=self.url.cases_get_prefix,
            headers={"Content-Type": "application/json"}
        )
        output = response.json()
        self.case_prefix = output['result']
        return output

    def case_list_attached_notebooks(self, case_id, results_only=False):
        body = {
            "id": helpers.format_case_id_with_prefix(case_id, self.case_prefix),
            "key": "case",
        }
        log.debug("Fetching attached notebooks")
        response = self._http_request(
            url=self.url.notebooks_attached,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=body,
            input_var=case_id
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
        body = {
            "notebookAttachmentIds": notebooks,
            "notebookAttachedEntityId": {
                "key": "case",
                "id": helpers.format_case_id_with_prefix(case_id, self.case_prefix),
            }
        }
        log.debug("Updating attached notebooks")
        response = self._http_request(
            url=self.url.notebooks_attach,
            method="PATCH",
            headers={"Content-Type": "application/json"},
            params={"libraryView": "all"},
            body=body,
            input_var=case_id
        )
        return response.json()

    # ToDo Update alert search and validation methods to match the updates I made here
    def cases_search_validate(self, query: str):
        if query:
            # First confirm that the query is valid
            body = {"queryType": "advanced", "query": query}
            log.debug("Validating search syntax")
            response = self._http_request(
                url=self.url.cases_search_validate,
                method="POST",
                headers={"Content-Type": "application/json"},
                body=body
            )
            response = response.json()
            is_invalid = response['result'].get('error')
            if is_invalid is None:
                raise exceptions.app.UnexpectedOutput('Unexpected response while validating query string.')
            elif is_invalid:
                raise exceptions.app.CaseQueryValidationError(response['result'].get('message'))

    # ToDo Update alert search and validation methods to match the updates I made here
    def case_search_advanced(self, query: str = None, limit: int = None, **kwargs):
        # Validate inputs
        if limit is None:
            limit = self.DEFAULT_CASE_RESULT_LIMIT
        elif limit == -1:
            limit = 999999
        elif not isinstance(limit, int):
            raise exceptions.validation.InputValidationError("Invalid input type for search limit", input_var=limit)

        body = {
            "pageNumber": 0,
            "pageSize": limit,
            "query": query or "",
            "includeTaskEntityType": True,
            "includeWorkflow": True
        }
        if kwargs:
            body.update(kwargs)
        log.debug("Executing case search")
        response = self._http_request(
            url=self.url.cases_search_advanced,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=body
        )
        return response.json()

    def alert_fetch(self, alert_id, return_raw=False, **kwargs):
        alert_id = helpers.format_alert_id(alert_id)
        url = self.url.alert_fetch.format(alert_id)
        # Send request, but disable immediate testing in order to do specialized testing first
        log.debug("Fetching alert")
        response = self._http_request(method="GET", url=url, test_response=False, **kwargs, input_var=alert_id)
        if return_raw:
            return response
        if response.status_code == 400 and re.search(r'Alert with id alert-\d+ doesn\'t exist', response.text):
            raise ValueError(f'No alert with ID {alert_id}')
        self.__standard_http_response_tests(response, url, input_var=alert_id)
        return response.json()

    def alerts_search_validate(self, query: str):
        if query:
            # First confirm that the query is valid
            body = {"queryType": "advanced", "query": query}
            log.debug("Validating search syntax")
            response = self._http_request(
                url=self.url.alerts_search_validate,
                method="POST",
                headers={"Content-Type": "application/json"},
                body=body
            )
            response = response.json()
            is_invalid = response['result'].get('error')
            if is_invalid is None:
                raise exceptions.app.UnexpectedOutput('Unexpected response while validating query string.')
            elif is_invalid:
                raise exceptions.app.AlertQueryValidationError(response['result'].get('message'))

    def alerts_search_advanced(self, query: str = None, limit: int = None, **kwargs):
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
        if kwargs:
            body.update(kwargs)
        log.debug("Searching alerts")
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
        log.debug("Pausing stream")
        response = self._http_request(method="POST", url=self.url.stream_pause, body=body, **kwargs, input_var=stream_id)
        return response.json()

    def stream_resume(self, stream_id, **kwargs):
        # Sanitize stream ID
        body = [f"stream-{helpers.format_stream_id(stream_id)}"]
        log.debug("Resuming stream")
        response = self._http_request(method="POST", url=self.url.stream_resume, body=body, **kwargs, input_var=stream_id)
        return response.json()

    def create_user(self, username, email, authentication_type, group_ids: list):
        body = {
            "username": username,
            "email": email,
            "userGroupIds": group_ids,
            "authenticationType": authentication_type or "password"
        }
        log.debug(f"Creating user: {username}")
        response = self._http_request(method="POST", url=self.url.user_create, body=body, input_var=username)
        return response.json()

    def delete_user(self, user_ids: list):
        log.debug(f"Deleting users by id: {', '.join([str(i) for i in user_ids])}")
        response = self._http_request(method="POST", url=self.url.user_delete, body=user_ids, input_var=user_ids)
        return response.json()

    def create_user_group(self, name: str, users: list = None, **kwargs):
        body = {"name": name, "users": users or [], **kwargs}
        log.debug(f"Creating user: {name}")
        response = self._http_request(method="POST", url=self.url.user_group_create, body=body, input_var=name)
        return response.json()

    def update_user_group(self, group_id: int, name: str, users: list = None, **kwargs):
        body = {"name": name, "users": users or [], **kwargs}
        log.debug(f"Creating user: {name}")
        response = self._http_request(method="PATCH", url=self.url.user_group.format(group_id), body=body, input_var=name)
        return response.json()

    def get_password_settings(self):
        log.debug("Fetching password settings")
        response = self._http_request(url=self.url.get_password_settings)
        return response.json()

    def update_password_settings(self, settings_dict):
        log.debug("Fetching password settings")
        response = self._http_request(method="PATCH", url=self.url.update_password_settings, body=settings_dict)
        return response.json()

    def reset_password(self, user_id):
        log.debug(f"Resetting password for user ID: {user_id}")
        response = self._http_request(method="POST", url=self.url.user_legacy.format(user_id), body={"method": "regeneratePassword", "parameters": {}})
        return response.json()

    def get_user_by_id(self, user_id):
        log.debug(f"Fetching user detail from ID: {user_id}")
        response = self._http_request(url=self.url.user_legacy.format(user_id))
        return response.json()


class FormattedObjects:
    def __init__(self, api: LogicHubAPI):
        self.__api = api

    @property
    def version(self):
        return super(self.__api).version

    @property
    def system_field_lh_linked_alerts(self) -> dict:
        field = None
        for f in self.__api.fields['result']['data']:
            if f.get('fieldName') == 'lh_linked_alerts':
                field = f
                break
        return field
        # raise exceptions.validation.VersionMinimumNotMet(min_version='m86', feature_label='linked alerts')

    @property
    def system_field_lh_linked_alerts_id(self):
        return int(self.system_field_lh_linked_alerts['id'].replace('field-', ''))

    @property
    def user_groups(self):
        groups = self.__api.list_user_groups(limit=None, hide_inactive=True)['result']['data']
        # convert the group ID to an int, rename field to 'id', and stick back at the top of the dict
        return [dict(**{'id': helpers.format_user_group_id(groups[n])}, **groups[n]) for n in range(len(groups))]

    @property
    def user_groups_by_id(self):
        return {g['usersGroupId']: g for g in self.user_groups}

    @property
    def user_groups_by_name(self):
        return {g['name']: g for g in self.user_groups}

    @property
    def user_groups_simple(self):
        return [{k: v for k, v in g.items() if k != 'entityTypePermissions'} for g in self.user_groups]

    @property
    def user_groups_simple_by_id(self):
        return {g['id']: g for g in self.user_groups_simple}

    @property
    def user_groups_simple_by_name(self):
        return {g['name']: g for g in self.user_groups_simple}

    @property
    def users(self):
        if self.__api.major_version < 96:
            kwargs = {"hide_inactive": True}
        else:
            kwargs = {"inactiveUsers": "onlyActive"}
        response = self.__api.list_users(limit=None, **kwargs)
        return response['result']['data']

    @property
    def users_by_id(self):
        users = self.users
        return {helpers.format_user_id(u): u for u in users}

    @property
    def users_by_name(self):
        users = self.users
        return {u['name']: u for u in users}

    def get_username_by_id(self, user_id):
        user = self.__api.get_user_by_id(user_id)
        return user["result"]["username"]
