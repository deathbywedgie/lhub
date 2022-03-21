from .base import LhBaseException
from requests.exceptions import HTTPError


class BaseAppError(LhBaseException, HTTPError):
    """Base exception for failures from interacting with LogicHub itself, including custom HTTP errors"""

    def __init__(self, message=None, *args, **kwargs):
        self.message = message or "HTTP error"
        super().__init__(self.message, *args, **kwargs)


class BatchNotFound(BaseAppError):
    """Batch ID not found"""

    __default_message = 'Batch not found'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class NotebookNotFound(BaseAppError):
    """Batch ID not found"""

    __default_message = 'Notebook not found'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class RuleSetNotFound(BaseAppError):
    """Rule set not found for the given search criteria"""

    __default_message = 'Rule set not found'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class StreamNotFound(BaseAppError):
    """Stream ID not found"""

    __default_message = 'Stream not found'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class UnexpectedOutput(BaseAppError):
    """Authentication Failed"""

    __default_message = 'Unexpected output returned'

    def __init__(self, message=None, *args, **kwargs):
        self.message = message or self.__default_message
        super().__init__(*args, **kwargs)
