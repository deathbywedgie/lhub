import datetime

DEFAULT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def epoch_time_to_str(time_sec, time_format=None):
    time_format = time_format if time_format else DEFAULT_TIME_FORMAT
    dt = datetime.datetime.fromtimestamp(time_sec)
    return dt.strftime(time_format)
