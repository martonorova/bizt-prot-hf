import os
import logging

app_root : str = os.getenv('SIFT_APP_ROOT', '~').rstrip('/').rstrip('\\')+'/SIFT_v1_0'

__tmp = os.getenv('SIFT_TS_DIFF_THRESHOLD', "2")
ts_diff_threshold: int = int(__tmp) if __tmp.isdigit() else 2

log_level = os.environ.get('SIFT_LOGLEVEL', 'INFO').upper()

show_messages = os.environ.get('SIFT_SHOW_MESSAGES', 'False').lower() in ('yes', 'true', 't', '1')