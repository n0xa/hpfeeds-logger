#!/usr/bin/python

import datetime
import time


def format(message):
    outmsg = dict()

    timestamp = datetime.datetime.isoformat(datetime.datetime.utcnow())
    if time.tzname[0] == 'UTC':
        timestamp += 'Z'
    outmsg['timestamp'] = timestamp

    for k, v in dict(message).items():
        if isinstance(v, bytes):
            outmsg[k] = v.decode('utf8')
        else:
            outmsg[k] = v

    if 'src_ip' in outmsg:
        outmsg['src'] = outmsg['src_ip']
        del outmsg['src_ip']

    if 'dest_ip' in outmsg:
        outmsg['dest'] = outmsg['dest_ip']
        del outmsg['dest_ip']

    d = [u'{}="{}"'.format(name, str(value).replace('"', '\\"')) for name, value in outmsg.items() if value]
    msg = ', '.join(d)

    return msg
