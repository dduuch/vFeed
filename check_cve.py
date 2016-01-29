#!/usr/bin/env python

from lib.core.methods import *
from lib.core.methods import CveInfo
from lib.core.update import Update
from config.stats import Stats
import re
import json

words=['libvirt', 'qemu']

Update().update()

def get_last_cve():
    stats = Stats()
    latest_cve = stats.get_latest()
    return latest_cve

def compile_words(cve_info):
    pattern = re.compile(r'(\S{4,})')
    return pattern.findall(cve_info)

def check_lists(cve_info):
    for cve in cve_info:
        if cve.lower() in words:
            return True

def check_if_cve_has_words(latest_cve):
    cve_vulnerability = []
    for cve in latest_cve:
        cve_info = CveInfo(cve).get_cve()
        cve_words = compile_words(cve_info[0]['summary'])
        if check_lists(cve_words):
            cve_vulnerability.append(cve_info[0]['id'])
    return cve_vulnerability


if __name__ == "__main__":

    last_cve = get_last_cve()
    cve = check_if_cve_has_words(last_cve)
    if cve:
        print "We are affected for this cve:"
        print cve
