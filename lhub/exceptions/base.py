class LhBaseException(BaseException):
    """There was a generic exception that occurred while handling your
    request.

    Catching this exception will catch *all* custom exceptions from this package
    """
    message = "An exception occurred"

    def __init__(self, *args, **kwargs):
        self.message = kwargs.get("message", self.message)
        self.input = kwargs.pop("input_var", None)
        self.url = kwargs.pop("url", None)
        self.last_response_status = kwargs.pop("last_response_status", None)
        self.last_response_text = kwargs.pop("last_response_status", None)
        super().__init__(*args, **kwargs)
