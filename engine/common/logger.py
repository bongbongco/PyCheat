"""
name        : logger.py
author      : hakbaby
function    : pycheat logger
"""

import time
import inspect
import logging

class AppFilter(logging.Filter):

    def filter(self, record):
        frm = inspect.stack()[6]
        mod = inspect.getmodule(frm[0])
        record.app_name = mod.__name__
        return True

class logger:

    def __init__(self, c=0, g=0, loggername=''):

        self.c = c

        self.logger = logging.getLogger(loggername)
        self.logger.setLevel(logging.INFO)
        self.logger.addFilter(AppFilter())

        self.fomatter = logging.Formatter("[%(asctime)s] %(message)s (%(app_name)s)", "%H:%M:%S")

        streamHandler = logging.StreamHandler()
        streamHandler.setFormatter(self.fomatter)
        self.logger.addHandler(streamHandler)

        if c > 0:
            self.file_stream()

    def file_stream(self):
        now = time.localtime()
        filename = '%04d-%02d-%02d_%02d-%02d-%02d.log' %(now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)
        fileHandler = logging.FileHandler(filename)
        fileHandler.setFormatter(self.fomatter)
        self.logger.addHandler(fileHandler)

    def log(self, message):
        message = "%s" %(message)
        self.logger.info(message)

