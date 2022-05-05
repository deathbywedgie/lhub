import logging


# Declaring these things all the time results in logging config changes that
# cannot easily be undone, so only perform them when invoked
def prep_generic_logger(level=None):
    # Only run once, though.
    if hasattr(prep_generic_logger, "done"):
        return
    level = level.upper().strip() if level else None
    logging.basicConfig(level=level)
    logger = logging.getLogger()
    if not level:
        logger.disabled = True
    prep_generic_logger.done = True
