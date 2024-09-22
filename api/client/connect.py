#!/usr/bin/env python3

import json
from .csocket import CSocket

_conf = {
    "socket": "/var/run/fail2ban/fail2ban.sock"
}

client = CSocket(_conf["socket"])

intervals = (
    ('y', 31536000),# 60 * 60 * 24 * 365
    ('w', 604800),  # 60 * 60 * 24 * 7
    ('d', 86400),    # 60 * 60 * 24
    ('h', 3600),    # 60 * 60
    ('m', 60),
    ('s', 1),
)

def display_time(seconds, granularity=1):
    #https://stackoverflow.com/a/24542445
    result = []

    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip('s')
            result.append("{}{}".format(value, name))
    return ', '.join(result[:granularity])
    
def _transform(data):
    details = {}
    for d in data:
        detail = {}
        key = d[0].lower().replace(" ", "_")
        value = d[1]
        detail[key] = value
        details.update(detail)

    return details

def parse_to_json(data, ipwithtime = False):
    if isinstance(data, str) and 'pong' in data:
        return {
            'details': {
                'pong': True
            }
        }

    if isinstance(data, int):
        return {
            'details': {
                'response': data
            }
        }

    details = {}
    if not ipwithtime:
        for d in data:
            detail = {}
            key = d[0].lower().replace(" ", "_")
            value = d[1]
            if isinstance(value, list):
                value = _transform(value)
            if isinstance(value, str) and ',' in value:
                value = value.split(", ")
            detail[key] = value
            details.update(detail)
    else:
        for d in data:
            detail = {}
            vals = d.split("\t")
            ip = vals[0].strip()
            end_date = vals[1].split(" = ")[1]
            ban_time = vals[1].split(" + ")[1].split(" = ")[0]
            detail[ip] = {"ban_time": display_time(int(ban_time)), "end_date": end_date}
            details.update(detail)
    
    return {
        'details': details
    }


def send_cmd(cmd):
    c = cmd.split()
    data = client.send(c)
    if isinstance(data[1], Exception):
        data = {}
    if data:
        if "--with-time" in cmd:
            return parse_to_json(data[1], ipwithtime = True)
        else:
            return parse_to_json(data[1])