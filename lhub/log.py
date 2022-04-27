import logging

logging.basicConfig(level="FATAL")
_DefaultLogger = logging.getLogger()
_DefaultLogger.disabled = True
