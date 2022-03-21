"""All authentication exceptions"""

from .app import BaseAppError


class AuthFailure(BaseAppError):
    """Authentication Failed"""

    __default_message = 'Authentication or authorization failure'

    def __init__(self, message=None, *args, **kwargs):
        self.message = message or self.__default_message
        super().__init__(*args, **kwargs)


class APIAuthFailure(AuthFailure):
    """Authentication Failed"""

    __default_message = 'API key is invalid for URL'

    def __init__(self, input_var, message=None, *args, **kwargs):
        self.input = input_var
        if self.input:
            self.__default_message += f": {self.input}"
        self.message = message or self.__default_message
        super().__init__(self.message, *args, **kwargs)


class APIAuthNotAuthorized(AuthFailure):
    """Authentication Failed"""

    __default_message = 'API auth not authorized or not supported for URL'

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
