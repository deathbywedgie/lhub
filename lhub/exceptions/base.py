class LhBaseException(BaseException):
    """There was a generic exception that occurred while handling your
    request.

    Catching this exception will catch *all* custom exceptions from this package
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
