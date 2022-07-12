from .base import LhBaseException


# ToDo Rework exceptions just like I did for lhub_cli
class BaseAppError(LhBaseException):
    """Base exception for failures from interacting with LogicHub itself, including custom HTTP errors"""
    message = "LogicHub returned an error"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class AlertQueryValidationError(BaseAppError):
    """Invalid format for alert queries"""
    message = 'Alert query is invalid'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class CaseQueryValidationError(BaseAppError):
    """Invalid format for case queries"""
    message = 'Case query is invalid'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class BatchNotFound(BaseAppError):
    """Batch/Batch ID not found"""
    message = 'Batch not found'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class NotebookNotFound(BaseAppError):
    """Batch ID not found"""
    message = 'Notebook not found'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class RuleSetNotFound(BaseAppError):
    """Rule set not found for the given search criteria"""
    message = 'Rule set not found'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class StreamNotFound(BaseAppError):
    """Stream ID not found"""
    message = 'Stream not found'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class UnexpectedOutput(BaseAppError):
    """Unexpected Output"""
    message = 'Unexpected output returned'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class UserGroupNotFound(BaseAppError):
    """User group not found"""
    message = 'User group not found'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class UserGroupAlreadyExists(BaseAppError):
    """User group already exists"""
    message = 'User group already exists'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class UserNotFound(BaseAppError):
    """User not found"""
    message = 'User not found'

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(input_var=user, *args, **kwargs)


class UserAlreadyExists(BaseAppError):
    """User already exists"""
    message = 'User already exists'

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(input_var=user, *args, **kwargs)
