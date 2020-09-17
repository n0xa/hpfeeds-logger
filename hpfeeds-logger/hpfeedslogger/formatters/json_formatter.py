import json
import datetime
import time

def format(message):
    msg = dict(message)
    t = datetime.datetime.isoformat(datetime.datetime.utcnow())
    if time.tzname[0] == 'UTC':
        t += 'Z'
    msg['timestamp'] = t
    return json.dumps(msg)
