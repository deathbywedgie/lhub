"""All authentication exceptions"""

from .app import BaseAppError


class AuthFailure(BaseAppError):
    """Authentication Failed"""
    message = 'Authentication or authorization failure'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class APIAuthFailure(AuthFailure):
    """API Token Authentication Failed"""
    message = 'API key is invalid for URL'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class APIAuthNotAuthorized(AuthFailure):
    """API Token Auth Not Authorized"""
    message = 'API token auth is not authorized, or token auth is not supported for the given URL'

    def __init__(self, input_var, *args, **kwargs):
        super().__init__(input_var=input_var, *args, **kwargs)


class PasswordAuthFailure(AuthFailure):
    """Password Authentication Failed"""
    message = 'Password authentication or authorization failure'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
