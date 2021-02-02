#! /usr/bin/env python
import calendar
import datetime
import email.utils
import re
import time

status_filename = "/var/local/keys-sync.status"

def check_content(status_filename):
    OK = 0
    WARN = 1
    CRIT = 2

    with open(status_filename, "r") as f:
        content = f.read()
    lines = content.split("\n")
    if len(lines) < 2:
        return (CRIT, "Status file " + status_filename + " is too short (expected at least 2 lines)")
    if lines[0] == "200 OK":
        m = re.match("^Expires: (.*)$", lines[1])
        if not m:
            return (CRIT, "Expected an Expires-Line in line 2 of status file " + status_filename)

        # # Python 3 only:
        # expired = email.utils.parsedate_to_datetime(m.group(1))

        # Workaround for additional Python 2 support:
        exp_tup = email.utils.parsedate_tz(m.group(1))
        expired = calendar.timegm(exp_tup[0:6]) - exp_tup[9]

        curtime = time.time()
        if expired + 24*60*60 <= curtime:
            return (CRIT, "The keys-sync status is expired since more than 24 hours (Got no update from ssh-key-authority during this time)")
        elif expired <= curtime:
            return (WARN, "The keys-sync status is expired (Got no update from ssh-key-authority before the expire-time was reached)")
        else:
            return (OK, "The keys-sync status is OK and up-to-date")
    else:
        try:
            empty_line = lines.index("")
            error_lines = lines[empty_line+1:]
            # Remove trailing empty line
            if len(error_lines) > 0 and error_lines[-1] == "":
                error_lines = error_lines[:-1]
            description = " / ".join(error_lines)
            return (CRIT, "Errors while syncing or scanning keys: " + description)
        except ValueError:
            return (CRIT, "The keys-sync status is set to error. (But no error description contained in status file)")

try:
    status, info = check_content(status_filename)
except BaseException as e:
    status = 2
    info = "Check script failed to execute: " + str(e)

print(str(status) + " keys_sync_status - " + info)
