#!/usr/bin/env python3

from requests.exceptions import HTTPError


class LhBaseException(BaseException):
    """There was a generic exception that occurred while handling your
    request.

    Catching this exception will catch *all* custom exceptions from this package
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class BaseAppError(LhBaseException, HTTPError):
    """Base exception for failures from interacting with LogicHub itself, including custom HTTP errors"""

    def __init__(self, message=None, *args, **kwargs):
        self.message = message or "HTTP error"
        super().__init__(self.message, *args, **kwargs)


class AuthFailure(BaseAppError):
    """Authentication Failed"""

    __default_message = 'Authentication or authorization failure'

    def __init__(self, message=None, *args, **kwargs):
        self.message = message or self.__default_message
        super().__init__(*args, **kwargs)


class APIAuthNotAuthorized(AuthFailure):
    """Authentication Failed"""

    __default_message = 'API auth not authorized or not supported for URL'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class APIAuthFailure(AuthFailure):
    """Authentication Failed"""

    __default_message = 'API key is invalid for URL'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class PasswordAuthFailure(AuthFailure):
    """Authentication Failed"""

    __default_message = 'Authentication or authorization failure'

    def __init__(self, message=None, *args, **kwargs):
        self.message = message or self.__default_message
        super().__init__(*args, **kwargs)


class UnexpectedOutput(BaseAppError):
    """Authentication Failed"""

    __default_message = 'Unexpected output returned'

    def __init__(self, message=None, *args, **kwargs):
        self.message = message or self.__default_message
        super().__init__(*args, **kwargs)


class RuleSetNotFound(BaseAppError):
    """Rule set not found for the given search criteria"""

    __default_message = 'Rule set not found'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class BatchNotFound(BaseAppError):
    """Batch ID not found"""

    __default_message = 'Unable to find batch with id'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class StreamNotFound(BaseAppError):
    """Stream ID not found"""

    __default_message = 'Unable to find stream with id'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


# ToDo Decide if I want to keep this
class EncryptionKeyError(LhBaseException, IOError):
    pass


class BaseFormatError(LhBaseException, ValueError):
    """Base exception for format errors for LogicHub resource objects"""

    def __init__(self, message=None, *args, **kwargs):
        self.message = message or "Invalid format for LH object"
        super().__init__(self.message, *args, **kwargs)


class InvalidAlertIdFormat(BaseFormatError):
    """Invalid format for notebook IDs"""
    __default_message = 'Invalid format for alert ID. Expected an ID number (as a string or number) or a string in the form of "alert-<number>".'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f" Received: {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class InvalidNotebookIdFormat(BaseFormatError):
    """Invalid format for notebook IDs"""
    __default_message = 'Invalid format for notebook ID. Expected an ID number (as a string or number) or a dict in the format of {"key": "notebook", "id": int}.'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f" Received: {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class InvalidPlaybookIdFormat(BaseFormatError):
    """Invalid format for notebook IDs"""
    __default_message = 'Invalid format for playbook ID. Expected an ID number (as a string or number) or a string in the form of "flow-<number>"'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f" Received: {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class InvalidStreamIdFormat(BaseFormatError):
    """Invalid format for Stream IDs"""
    __default_message = 'Invalid format for stream ID. Expected an ID number (as a string or number) or a string in the form of "stream-<number>".'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f" Received: {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


# ToDo Revisit this and add the expected format to the default message.
class InvalidRuleFormat(BaseFormatError):
    """Invalid format for scoring rule"""
    __default_message = 'Invalid format for scoring rule field mappings.'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f" Received: {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class BaseValidationError(LhBaseException):
    """Base exception for format errors for LogicHub resource objects"""

    def __init__(self, message=None, *args, **kwargs):
        self.message = message or "Input validation failed"
        super().__init__(self.message, *args, **kwargs)


class AlertQueryValidationError(BaseValidationError, BaseAppError):
    """Invalid format for notebook IDs"""
    __default_message = 'Alert query is invalid.'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f" Detail: {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class VersionMinimumNotMet(BaseValidationError):
    """Minimum version not met"""
    __default_message = 'Requested action ({}) requires a minimum LogicHub version of {}.'

    def __init__(self, min_version, feature_label, *args, **kwargs):
        self.message = self.__default_message.format(feature_label, min_version)
        self.id = feature_label
        super().__init__(self.message, *args, **kwargs)


# All authentication exceptions
class Auth:
    BaseAuthFailure = AuthFailure
    APIAuthFailure = APIAuthFailure
    APIAuthNotAuthorized = APIAuthNotAuthorized
    PasswordAuthFailure = PasswordAuthFailure


# Input formatting exceptions
class Formatting:
    BaseFormatError = BaseFormatError
    InvalidAlertIdFormat = InvalidAlertIdFormat
    InvalidNotebookIdFormat = InvalidNotebookIdFormat
    InvalidPlaybookIdFormat = InvalidPlaybookIdFormat
    InvalidRuleFormat = InvalidRuleFormat
    InvalidStreamIdFormat = InvalidStreamIdFormat


class Validation:
    BaseValidationError = BaseValidationError
    AlertQueryValidationError = AlertQueryValidationError
    VersionMinimumNotMet = VersionMinimumNotMet
