class LhBaseException(BaseException):
    """There was a generic exception that occurred while handling your
    request.

    Catching this exception will catch *all* custom exceptions from this package
    """
    message = "An exception occurred"

    def __init__(self, *args, **kwargs):
        self.input = kwargs.pop("input_var", None)
        if args:
            self.message = args[0]
        elif self.input:
            self.message += f": {self.input}"
        if not args:
            args = [self.message]

        self.url = kwargs.pop("url", None)
        self.last_response_status = kwargs.pop("last_response_status", None)
        self.last_response_text = kwargs.pop("last_response_status", None)
        super().__init__(*args, **kwargs)
