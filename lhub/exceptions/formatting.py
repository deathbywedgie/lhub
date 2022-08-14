from .base import LhBaseException


class BaseFormatError(LhBaseException, ValueError):
    """Base exception for format errors for LogicHub resource objects"""
    message = "Invalid format for LH object"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class InvalidAlertIdFormat(BaseFormatError):
    """Invalid format for alert ID"""
    message = 'Invalid format for alert ID'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class InvalidBatchIdFormat(BaseFormatError):
    """Invalid format for batch ID"""
    message = 'Invalid format for batch ID'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class InvalidCaseIdFormat(BaseFormatError):
    """Invalid format for case ID"""
    message = 'Invalid format for case ID'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class InvalidConnectionIdFormat(BaseFormatError):
    """Invalid format for connection ID"""
    message = 'Invalid format for connection ID'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class InvalidNotebookIdFormat(BaseFormatError):
    """Invalid format for notebook IDs"""
    message = 'Invalid format for notebook ID'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class InvalidPlaybookIdFormat(BaseFormatError):
    """Invalid format for notebook IDs"""
    message = 'Invalid format for playbook ID'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class InvalidRuleScore(BaseFormatError):
    """Invalid score for scoring rule"""
    message = 'Invalid score for scoring rule'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


# ToDo Add the expected format to the default message.
class InvalidRuleFormat(BaseFormatError):
    """Invalid format for scoring rule"""
    message = 'Invalid format for scoring rule field mappings.'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class InvalidRuleSetIdFormat(BaseFormatError):
    """Invalid format for rule set ID"""
    message = 'Invalid format for rule set ID'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class InvalidStreamIdFormat(BaseFormatError):
    """Invalid format for Stream IDs"""
    message = 'Invalid format for stream ID'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class InvalidUserIdFormat(BaseFormatError):
    """Invalid format for user IDs"""
    message = 'Invalid format for user ID'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class InvalidVersionFormat(BaseFormatError):
    """Invalid Format for LogicHub Version"""
    message = 'Invalid format for product version'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class InvalidWorkflowIdFormat(BaseFormatError):
    """Invalid Workflow ID"""
    message = 'Invalid format for workflow ID'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)
