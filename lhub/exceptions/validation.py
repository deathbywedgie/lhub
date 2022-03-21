from .base import LhBaseException
from .app import BaseAppError


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
