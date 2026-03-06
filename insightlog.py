import re
import calendar
from datetime import datetime

# --------------------------------------
# Improved error and warning logging
# --------------------------------------

import logging

logging.basicConfig(
    filename='insightlog.log',
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# --------------------------------------
# Service settings
# --------------------------------------

DEFAULT_NGINX = {
    'type': 'web0',
    'dir_path': '/var/log/nginx/',
    'accesslog_filename': 'access.log',
    'errorlog_filename': 'error.log',
    'dateminutes_format': '[%d/%b/%Y:%H:%M',
    'datehours_format': '[%d/%b/%Y:%H',
    'datedays_format': '[%d/%b/%Y',
    'request_model': (r'(\d+\.\d+\.\d+\.\d+)\s-\s-\s'
                      r'\[(.+)\]\s'
                      r'"?(\w+)\s(.+)\s\w+/.+"'
                      r'\s(\d+)\s'
                      r'\d+\s"(.+)"\s'
                      r'"(.+)"'),
    'date_pattern': r'(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+)',
    'date_keys': {'day': 0, 'month': 1, 'year': 2, 'hour': 3, 'minute': 4, 'second': 5}
}

DEFAULT_APACHE2 = {
    'type': 'web0',
    'dir_path': '/var/log/apache2/',
    'accesslog_filename': 'access.log',
    'errorlog_filename': 'error.log',
    'dateminutes_format': '[%d/%b/%Y:%H:%M',
    'datehours_format': '[%d/%b/%Y:%H',
    'datedays_format': '[%d/%b/%Y',
    'request_model': (r'(\d+\.\d+\.\d+\.\d+)\s-\s-\s'
                      r'\[(.+)\]\s'
                      r'"?(\w+)\s(.+)\s\w+/.+"'
                      r'\s(\d+)\s'
                      r'\d+\s"(.+)"\s'
                      r'"(.+)"'),
    'date_pattern': r'(\d+)/(\w+)/(\d+):(\d+):(\d+):(\d+)',
    'date_keys': {'day': 0, 'month': 1, 'year': 2, 'hour': 3, 'minute': 4, 'second': 5}
}

DEFAULT_AUTH = {
    'type': 'auth',
    'dir_path': '/var/log/',
    'accesslog_filename': 'auth.log',
    'dateminutes_format': '%b %e %H:%M:',
    'datehours_format': '%b %e %H:',
    'datedays_format': '%b %e ',
    'request_model': (r'(\w+\s\s\d+\s\d+:\d+:\d+)\s'
                      r'\w+\s(\w+)\[\d+\]:\s'
                      r'(.+)'),
    'date_pattern': r'(\w+)\s(\s\d+|\d+)\s(\d+):(\d+):(\d+)',
    'date_keys': {'month': 0, 'day': 1, 'hour': 2, 'minute': 3, 'second': 4}
}

SERVICES_SWITCHER = {
    'nginx': DEFAULT_NGINX,
    'apache2': DEFAULT_APACHE2,
    'auth': DEFAULT_AUTH
}

IPv4_REGEX = r'(\d+.\d+.\d+.\d+)'
AUTH_USER_INVALID_USER = r'(?i)invalid\suser\s(\w+)\s'
AUTH_PASS_INVALID_USER = r'(?i)failed\spassword\sfor\s(\w+)\s'


# --------------------------------------
# Validators
# --------------------------------------

def is_valid_year(year):
    return 2030 >= year > 1970

def is_valid_month(month):
    return 12 >= month > 0

def is_valid_day(day):
    return 31 >= day > 0

def is_valid_hour(hour):
    return (hour == '*') or (23 >= hour >= 0)

def is_valid_minute(minute):
    return (minute == '*') or (59 >= minute >= 0)


# --------------------------------------
# Utility functions
# --------------------------------------

def get_service_settings(service_name):
    if service_name in SERVICES_SWITCHER:
        return SERVICES_SWITCHER.get(service_name)
    else:
        raise Exception(f"Service '{service_name}' doesn't exist!")


def get_date_filter(settings, minute=datetime.now().minute, hour=datetime.now().hour,
                    day=datetime.now().day, month=datetime.now().month,
                    year=datetime.now().year):

    if not is_valid_year(year) or not is_valid_month(month) or not is_valid_day(day) \
            or not is_valid_hour(hour) or not is_valid_minute(minute):
        raise Exception("Date elements aren't valid")

    if minute != '*' and hour != '*':
        return datetime(year, month, day, hour, minute).strftime(settings['dateminutes_format'])

    if minute == '*' and hour != '*':
        return datetime(year, month, day, hour).strftime(settings['datehours_format'])

    if minute == '*' and hour == '*':
        return datetime(year, month, day).strftime(settings['datedays_format'])

    raise Exception("Date elements aren't valid")


def check_match(line, filter_pattern, is_regex=False, is_casesensitive=True, is_reverse=False):
    if is_regex:
        check_result = re.match(filter_pattern, line) if is_casesensitive \
            else re.match(filter_pattern, line, re.IGNORECASE)
    else:
        check_result = (filter_pattern in line) if is_casesensitive else (filter_pattern.lower() in line.lower())

    return not check_result if is_reverse else check_result


def filter_data(log_filter, data=None, filepath=None, is_casesensitive=True, is_regex=False, is_reverse=False):
    return_data = ""

    if filepath:
        try:
            with open(filepath, 'r') as file_object:
                for line in file_object:
                    if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                        return_data += line
            return return_data
        except (IOError, EnvironmentError) as e:
            logging.error(f"Could not open file '{filepath}': {e}")
            return None

    if data:
        for line in data.splitlines():
            if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                return_data += line + "\n"
        return return_data

    raise Exception("Data and filepath values are NULL!")


# --------------------------------------
# ORIGINAL _get_auth_year() (Option B)
# --------------------------------------

def _get_auth_year():
    """Return the year when the requests happened (simple version)."""
    if datetime.now().month == 1 and datetime.now().day == 1 and datetime.now().hour == 0:
        return datetime.now().year - 1
    return datetime.now().year


# --------------------------------------
# Date parsing
# --------------------------------------

def _get_iso_datetime(str_date, pattern, keys):
    months_dict = {v: k for k, v in enumerate(calendar.month_abbr)}
    matches = re.findall(pattern, str_date)

    if not matches:
        logging.warning(f"Malformed date skipped: '{str_date}' did not match pattern '{pattern}'")
        raise ValueError(f"Date pattern '{pattern}' did not match '{str_date}'")

    a_date = matches[0]

    if 'year' in keys:
        year = int(a_date[keys['year']])
    else:
        year = _get_auth_year()

    d_datetime = datetime(
        year,
        months_dict[a_date[keys['month']]],
        int(a_date[keys['day']].strip()),
        int(a_date[keys['hour']]),
        int(a_date[keys['minute']]),
        int(a_date[keys['second']])
    )

    return d_datetime.isoformat(' ')


# --------------------------------------
# Request parsing
# --------------------------------------

def get_web_requests(data, pattern, date_pattern=None, date_keys=None):
    if date_pattern and not date_keys:
        raise Exception("date_keys is not defined")

    requests_dict = re.findall(pattern, data, flags=re.IGNORECASE)
    requests = []

    for request_tuple in requests_dict:
        try:
            if date_pattern:
                str_datetime = _get_iso_datetime(request_tuple[1], date_pattern, date_keys)
            else:
                str_datetime = request_tuple[1]
        except Exception as e:
            logging.warning(f"Skipping malformed web request: {request_tuple} ({e})")
            continue

        requests.append({
            'DATETIME': str_datetime,
            'IP': request_tuple[0],
            'METHOD': request_tuple[2],
            'ROUTE': request_tuple[3],
            'CODE': request_tuple[4],
            'REFERRER': request_tuple[5],
            'USERAGENT': request_tuple[6]
        })

    return requests


def get_auth_requests(data, pattern, date_pattern=None, date_keys=None):
    requests_dict = re.findall(pattern, data)
    requests = []

    for request_tuple in requests_dict:
        try:
            if date_pattern:
                str_datetime = _get_iso_datetime(request_tuple[0], date_pattern, date_keys)
            else:
                str_datetime = request_tuple[0]
        except Exception as e:
            logging.warning(f"Skipping malformed auth request: {request_tuple} ({e})")
            continue

        parsed = analyze_auth_request(request_tuple[2])
        parsed['DATETIME'] = str_datetime
        parsed['SERVICE'] = request_tuple[1]
        requests.append(parsed)

    return requests


def analyze_auth_request(request_info):
    ipv4 = re.findall(IPv4_REGEX, request_info)
    is_preauth = '[preauth]' in request_info.lower()
    invalid_user = re.findall(AUTH_USER_INVALID_USER, request_info)
    invalid_pass_user = re.findall(AUTH_PASS_INVALID_USER, request_info)
    is_closed = 'connection closed by ' in request_info.lower()

    return {
        'IP': ipv4[0] if ipv4 else None,
        'INVALID_USER': invalid_user[0] if invalid_user else None,
        'INVALID_PASS_USER': invalid_pass_user[0] if invalid_pass_user else None,
        'IS_PREAUTH': is_preauth,
        'IS_CLOSED': is_closed
    }


# --------------------------------------
# Filtering
# --------------------------------------

def apply_filters(filters, data=None, filepath=None):
    if filepath:
        try:
            with open(filepath, 'r') as file_object:
                filtered_lines = [
                    line for line in file_object
                    if check_all_matches(line, filters)
                ]
                return ''.join(filtered_lines)
        except (IOError, EnvironmentError) as e:
            logging.error(f"Could not open file '{filepath}': {e}")
            return None

    if data:
        filtered_lines = [
            line + "\n" for line in data.splitlines()
            if check_all_matches(line, filters)
        ]
        return ''.join(filtered_lines)

    raise Exception("Either data or filepath must be provided")


def check_all_matches(line, filter_patterns):
    if not filter_patterns:
        return True

    return all(check_match(line=line, **pattern_data) for pattern_data in filter_patterns)


# --------------------------------------
# Main request dispatcher
# --------------------------------------

def get_requests(service, data=None, filepath=None, filters=None):
    settings = get_service_settings(service)

    if not filepath and not data:
        filepath = settings['dir_path'] + settings['accesslog_filename']

    if filters:
        filtered_data = apply_filters(filters, data=data, filepath=filepath)
    else:
        if filepath:
            try:
                with open(filepath, 'r') as f:
                    filtered_data = f.read()
            except (IOError, EnvironmentError) as e:
                logging.error(f"Could not open file '{filepath}': {e}")
                return None
        else:
            filtered_data = data

    if not filtered_data:
        return []

    request_pattern = settings['request_model']
    date_pattern = settings['date_pattern']
    date_keys = settings['date_keys']

    if settings['type'] == 'web0':
        return get_web_requests(filtered_data, request_pattern, date_pattern, date_keys)

    if settings['type'] == 'auth':
        return get_auth_requests(filtered_data, request_pattern, date_pattern, date_keys)

    return None


# --------------------------------------
# CLI entry point
# --------------------------------------

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Analyze server log files (nginx, apache2, auth)")
    parser.add_argument('--service', required=True, choices=['nginx', 'apache2', 'auth'], help='Type of log to analyze')
    parser.add_argument('--logfile', required=True, help='Path to the log file')
    parser.add_argument('--filter', required=False, default=None, help='String to filter log lines')
    args = parser.parse_args()

    filters = []
    if args.filter:
        filters.append({
            'filter_pattern': args.filter,
            'is_casesensitive': True,
            'is_regex': False,
            'is_reverse': False
        })

    requests = get_requests(args.service, filepath=args.logfile, filters=filters)
    if requests:
        for req in requests:
            print(req)