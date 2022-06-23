from .base import LhBaseException
from .app import BaseAppError


class BaseValidationError(LhBaseException):
    """Base exception for format errors for LogicHub resource objects"""
    message = "Validation failure"

    def __init__(self, message=None, *args, **kwargs):
        self.message = message or "Input validation failed"
        super().__init__(self.message, *args, **kwargs)


class InputValidationError(BaseValidationError, ValueError):
    """Invalid format for input"""
    message = 'Invalid input'

    def __init__(self, input_var, action_description=None, *args, **kwargs):
        if action_description:
            self.message += f" for {action_description}"
            self.action_description = action_description
        super().__init__(input_var=input_var, *args, **kwargs)


class ResponseValidationError(BaseValidationError, BaseAppError):
    """Unexpected schema for LogicHub API response"""
    message = 'API response received in unexpected format/schema'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class VersionMinimumNotMet(BaseValidationError):
    """Minimum version not met"""
    message = 'Requested action ({}) requires a minimum LogicHub version of {}.'

    def __init__(self, min_version, feature_label, *args, **kwargs):
        self.message = self.message.format(feature_label, min_version)
        self.id = feature_label
        super().__init__(self.message, *args, **kwargs)
