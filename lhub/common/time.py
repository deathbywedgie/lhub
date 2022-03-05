import datetime
import pytz


DEFAULT_TIME_ZONE = "US/Pacific"
DEFAULT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def epoch_time_to_str(time_sec, time_format=None, timezone=None):
    timezone = timezone or DEFAULT_TIME_ZONE
    time_format = time_format if time_format else DEFAULT_TIME_FORMAT
    dt = datetime.datetime.fromtimestamp(time_sec)
    dt = pytz.timezone(timezone).localize(dt)
    return dt.strftime(time_format)
