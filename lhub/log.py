import sys

_LOG_LEVEL_MAP = {"debug": 7, "info": 6, "notice": 5, "warn": 4, "error": 3, "crit": 2, "alert": 1, "fatal": 0}


# Placeholder for real logging
class Logger:
    __log_level = "INFO"
    default_log_level = "INFO"

    _LOG_LEVELS = _LOG_LEVEL_MAP.keys()

    def __init__(self, session_prefix=None, log_level=None):
        self.log_level = log_level if log_level else self.default_log_level
        # self.session_prefix = session_prefix or ""
        self.session_prefix = (session_prefix or self.generate_logger_prefix()).strip()

    def generate_logger_prefix(self):
        return f"[{hex(id(self))}] "

    @property
    def log_level(self):
        if self.__log_level.lower() not in self._LOG_LEVELS:
            raise ValueError(f"Invalid log level: {self.__log_level}")
        return self.__log_level

    @log_level.setter
    def log_level(self, val: str):
        if val.lower() not in self._LOG_LEVELS:
            raise ValueError(f"Invalid log level: {val}")
        self.__log_level = val.upper()

    def __print(self, level, msg):
        level_num = _LOG_LEVEL_MAP[level.lower()]
        output_file = sys.stdout if level_num >= 5 else sys.stderr
        current_level_num = _LOG_LEVEL_MAP[self.log_level.lower()]
        if current_level_num >= level_num:
            print(f"[{level.upper()}] {self.session_prefix} {msg}", file=output_file)
        if level_num == 0:
            sys.exit(1)

    def debug(self, msg):
        self.__print("debug", msg)

    def info(self, msg):
        self.__print("info", msg)

    def notice(self, msg):
        self.__print("notice", msg)

    def warn(self, msg):
        self.__print("warn", msg)

    def error(self, msg):
        self.__print("error", msg)

    def crit(self, msg):
        self.__print("crit", msg)

    def alert(self, msg):
        self.__print("alert", msg)

    def fatal(self, msg):
        self.__print("fatal", msg)

    @staticmethod
    def print(msg):
        """
        Explicit print option so this can be further controlled later if needed

        :param msg:
        :return:
        """
        print(msg)
