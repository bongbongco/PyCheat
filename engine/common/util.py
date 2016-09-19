"""
name        : util.py
author      : hakbaby
function    : using python functions
"""

def thread(target, args=[]):
    
    import threading

    thread = threading.Thread(target=target, args=args)
    thread.start()

    return thread
