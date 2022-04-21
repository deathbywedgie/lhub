from .base import LhBaseException


# ToDo Notebooks have a supported dict format of {"key": "notebook", "id": int}. Look into making the same for other resource types

class BaseFormatError(LhBaseException, ValueError):
    """Base exception for format errors for LogicHub resource objects"""

    def __init__(self, message=None, *args, **kwargs):
        self.message = message or "Invalid format for LH object"
        super().__init__(self.message, *args, **kwargs)


class InvalidAlertIdFormat(BaseFormatError):
    """Invalid format for alert IDs"""
    __default_message = 'Invalid format for alert ID. Expected an ID number (as a string or number) or a string in the form of "alert-<number>".'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f" Received: {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class InvalidCaseIdFormat(BaseFormatError):
    """Invalid format for case IDs"""
    __default_message = 'Invalid format for case ID. Expected an ID number (as a string or number) or a string in the form of "<case_prefix>-<number>"'

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


class InvalidRuleScore(BaseFormatError):
    """Invalid score for scoring rule"""
    __default_message = 'Invalid score for scoring rules.'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f" Received: {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


# ToDo Add the expected format to the default message.
class InvalidRuleFormat(BaseFormatError):
    """Invalid format for scoring rule"""
    __default_message = 'Invalid format for scoring rule field mappings.'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f" Received: {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class InvalidRuleSetIdFormat(BaseFormatError):
    """Invalid format for rule set ID"""
    __default_message = 'Invalid format for scoring rule field mappings.'

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


class InvalidUserIdFormat(BaseFormatError):
    """Invalid format for Stream IDs"""
    __default_message = 'Invalid format for user ID.'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f" Received: {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class InvalidVersionFormat(BaseFormatError):
    """Invalid format for Stream IDs"""
    __default_message = 'Invalid format for product version'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": \"{self.input}\""
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class InvalidWorkflowIdFormat(BaseFormatError):
    """Invalid format for Stream IDs"""
    __default_message = 'Invalid format for workflow ID'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)
