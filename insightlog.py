import re
import calendar
from datetime import datetime, timedelta
import argparse
import sys
import csv
import json
import os
import logging ### for error and warning logging ###

logging.basicConfig(
    filename='insightlog.log',
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Service settings
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

IPv4_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
AUTH_USER_INVALID_USER = r'(?i)invalid\suser\s(\w+)\s'
AUTH_PASS_INVALID_USER = r'(?i)failed\spassword\sfor\s(\w+)\s'



def start_wizard():
    print("\n--- InsightLog Wizard ---")
    # Uses Settings as Suggestion
    log_type = input("Log-Typ (nginx/apache2/auth) [nginx]: ") or "nginx"
    file_path = input(f"Path towards File [{DEFAULT_NGINX['dir_path']}access.log]: ") or (DEFAULT_NGINX['dir_path'] + "access.log")
    return file_path, log_type


# Validator functions
def is_valid_year(year):
    """Check if year's value is valid"""
    return 2030 >= year > 1970


def is_valid_month(month):
    """Check if month's value is valid"""
    return 12 >= month > 0


def is_valid_day(day, month, year):
    try:
        datetime(year, month, day)
        return True
    except ValueError:
        return False


def is_valid_hour(hour):
    """Check if hour value is valid"""
    return (hour == '*') or (23 >= hour >= 0)


def is_valid_minute(minute):
    """Check if minute value is valid"""
    return (minute == '*') or (59 >= minute >= 0)



# Utility functions
def get_service_settings(service_name):
    """Get default settings for the said service"""
    if service_name in SERVICES_SWITCHER:
        return SERVICES_SWITCHER.get(service_name)
    else:
        raise ValueError(f'Service "{service_name}" does not exist')


def get_date_filter(settings, minute=None, hour=None, day=None, month=None, year=None):

    now = datetime.now()
    minute = now.minute if minute is None else minute
    hour   = now.hour   if hour   is None else hour
    day    = now.day    if day    is None else day
    month  = now.month  if month  is None else month
    year   = now.year   if year   is None else year

    if minute != '*' and not isinstance(minute, int):
        raise TypeError("minute must be int or '*'")
    if hour != '*' and not isinstance(hour, int):
        raise TypeError("hour must be int or '*'")
    if day != '*' and not isinstance(day, int):
        raise TypeError("day must be int or '*'")
    if month != '*' and not isinstance(month, int):
        raise TypeError("month must be int or '*'")
    if year != '*' and not isinstance(year, int):
        raise TypeError("year must be int or '*'")

    """Get the date pattern that can be used to filter data from logs based on the params"""
    if not is_valid_year(year) or not is_valid_month(month) or not is_valid_day(day, month, year) \
            or not is_valid_hour(hour) or not is_valid_minute(minute):
        raise ValueError("Date elements aren't valid")

    if minute != '*' and hour != '*':
        date_format = settings['dateminutes_format']
        date_filter = datetime(year, month, day, hour, minute).strftime(date_format)
    elif minute == '*' and hour != '*':
        date_format = settings['datehours_format']
        date_filter = datetime(year, month, day, hour).strftime(date_format)
    elif minute == '*' and hour == '*':
        date_format = settings['datedays_format']
        date_filter = datetime(year, month, day).strftime(date_format)
    else:
        raise ValueError("Date elements aren't valid")
    return date_filter


def check_match(line, filter_pattern, is_regex=False, is_casesensitive=True, is_reverse=False):
    """Check if line contains/matches filter pattern"""
    if is_regex:
        check_result = re.search(filter_pattern, line) if is_casesensitive \
            else re.search(filter_pattern, line, re.IGNORECASE) #THE BUG FIXED re.match-->re.search
    else:
        check_result = (filter_pattern in line) if is_casesensitive else (filter_pattern.lower() in line.lower())
    if is_reverse:
        return not check_result
    return check_result


def filter_data(log_filter, data=None, filepath=None, is_casesensitive=True, is_regex=False, is_reverse=False):
    """Filter received data/file content and return the results"""
    return_data = ""
    if filepath:
        try:
            with open(filepath, 'r') as file_object:
                for line in file_object:
                    if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                        return_data += line
            return return_data
        except (IOError, EnvironmentError) as e:
            logging.error(f"Could not open file '{filepath}': {e}") ### for error and warning logging ###
            return None
    elif data:
        for line in data.splitlines():
            if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                return_data += line+"\n"
        return return_data
    else:
        raise Exception("Data and filepath values are NULL!")

# ------------------------------------------------------------------
# FIXED _get_auth_year() flawed year detection logic (for AUTH LOGS)
# ------------------------------------------------------------------

def _get_auth_year(log_month, log_day, log_hour, log_minute, log_second, max_future_days=7):
    """Return the year when the requests happened"""
    now = datetime.now()
    current_year = now.year

    try:
        month_num = list(calendar.month_abbr).index(log_month)
    except ValueError:
        raise ValueError(f"Invalid month abbreviation in auth log: {log_month!r}")

    candidate = datetime(
        current_year,
        month_num,
        int(log_day),
        int(log_hour),
        int(log_minute),
        int(log_second),
    )

    if candidate - now > timedelta(days=max_future_days):
        return current_year - 1

    return current_year


def _get_iso_datetime(str_date, pattern, keys):
    """Change raw datetime from logs to ISO 8601 format."""
    months_dict = {v: k for k, v in enumerate(calendar.month_abbr)}
    matches = re.findall(pattern, str_date)
    if not matches:
        logging.warning(f"Malformed date skipped: '{str_date}' did not match pattern '{pattern}'") ### for error and warning logging ###
        raise ValueError(f"Date pattern '{pattern}' did not match '{str_date}'")
    a_date = matches[0]

    if 'year' in keys:
        year = int(a_date[keys['year']])
    else:
        year = _get_auth_year(
            a_date[keys['month']],
            a_date[keys['day']].strip(),
            a_date[keys['hour']],
            a_date[keys['minute']],
            a_date[keys['second']],
        )

    d_datetime = datetime(
        year,
        months_dict[a_date[keys['month']]],
        int(a_date[keys['day']].strip()),
        int(a_date[keys['hour']]),
        int(a_date[keys['minute']]),
        int(a_date[keys['second']]))

    return d_datetime.isoformat(' ')


# refactored function
def get_web_request(data, pattern, date_pattern=None, date_keys=None):
    """Analyze data (from the logs) and return list of requests formatted as the model (pattern) defined."""
    if date_pattern and not date_keys:
        raise Exception("date_keys is not defined")

    request_match = re.match(pattern, data, flags=re.IGNORECASE)

    if not request_match:
        return None

    if date_pattern:
        str_datetime = _get_iso_datetime(request_match.group(2), date_pattern, date_keys)
    else:
        str_datetime = request_match.group(2)

    result={
        'DATETIME': str_datetime,
        'IP': request_match.group(1),
        'METHOD': request_match.group(3),
        'ROUTE': request_match.group(4),
        'CODE': request_match.group(5),
        'REFERRER': request_match.group(6),
        'USERAGENT': request_match.group(7)
    }
    return result

# refactored function
def get_auth_request(data, pattern, date_pattern=None, date_keys=None):
    """Analyze data (from the logs) and return list of auth requests formatted as the model (pattern) defined."""
    request_match = re.match(pattern, data)

    if not request_match:
        return None

    if date_pattern:
        str_datetime = _get_iso_datetime(request_match.group(1), date_pattern, date_keys)
    else:
        str_datetime = request_match.group(1)

    data = analyze_auth_request(request_match.group(3))
    data['DATETIME'] = str_datetime
    data['SERVICE'] = request_match.group(2)
    return data


def analyze_auth_request(request_info):
    """Analyze request info and returns main data (IP, invalid user, invalid password's user, is_preauth, is_closed)"""
    ipv4 = re.findall(IPv4_REGEX, request_info)
    is_preauth = '[preauth]' in request_info.lower()
    invalid_user = re.findall(AUTH_USER_INVALID_USER, request_info)
    invalid_pass_user = re.findall(AUTH_PASS_INVALID_USER, request_info)
    is_closed = 'connection closed by ' in request_info.lower()
    return {'IP': ipv4[0] if ipv4 else None,
            'INVALID_USER': invalid_user[0] if invalid_user else None,
            'INVALID_PASS_USER': invalid_pass_user[0] if invalid_pass_user else None,
            'IS_PREAUTH': is_preauth,
            'IS_CLOSED': is_closed}


# Simplified analyzer functions (replacing the class)
def apply_filters(filters, data=None, filepath=None):
    """Apply all filters to data or file and return filtered results"""
    if filepath:
        try:
            with open(filepath, 'r') as file_object:
                filtered_lines = []
                for line in file_object:
                    if check_all_matches(line, filters):
                        filtered_lines.append(line)
                return ''.join(filtered_lines)
        except (IOError, EnvironmentError) as e:
            logging.error(f"Could not open file '{filepath}': {e}") ### for error and warning logging ###
            return None
    elif data:
        filtered_lines = []
        for line in data.splitlines():
            if check_all_matches(line, filters):
                filtered_lines.append(line + "\n")
        return ''.join(filtered_lines)
    else:
        raise Exception("Either data or filepath must be provided")


def check_all_matches(line, filter_patterns):
    """Check if line contains/matches all filter patterns"""
    if not filter_patterns:
        return True
    result = True
    for pattern_data in filter_patterns:
        tmp_result = check_match(line=line, **pattern_data)
        result = result and tmp_result
    return result


def progress_bar(total, current, last_percent):
    if total <= 0:
        logging.error(f"cannot divide through {total}")
        raise ValueError("Dividing error in progress-bar")
    percent = (current / total) * 100
    percent_int = int(percent)

    bar_width = 30
    filled = int((percent_int / 100) * bar_width)
    bar = "#" * filled + "-" * (bar_width - filled)

    if percent_int > last_percent:
        print(f"[{bar}] {percent_int}%", end="\r", flush=True)
        last_percent = percent_int

    return last_percent


# refactored function
def get_requests(service, data=None, filepath=None, filters=None):
    """Analyze data and return list of requests. Main function to get parsed requests."""
    settings = get_service_settings(service)

    request_pattern = settings['request_model']
    date_pattern = settings['date_pattern']
    date_keys = settings['date_keys']

    requests = []
    last_percent = -1

    # Choose parser based on type
    if settings['type'] == 'web0':
        parser = get_web_request
    elif settings['type'] == 'auth':
        parser = get_auth_request
    else:
        return None

    if not filepath and data is None:
        filepath = settings['dir_path'] + settings['accesslog_filename']

    if filepath:
        filesize = os.path.getsize(filepath)
        try:
            with open(filepath, 'r') as file:
                line_number = 0
                line = file.readline()

                while line:
                    line_number += 1
                    current_bytes = file.tell()
                    last_percent = progress_bar(filesize, current_bytes, last_percent)

                    try:
                        if filters and not check_all_matches(line, filters):
                            line = file.readline()
                            continue

                        entry = parser(line, request_pattern, date_pattern, date_keys)
                        if entry:
                            requests.append(entry)

                    except Exception as e:
                        logging.warning(
                            f"{settings['type']} parse error at line {line_number}: {line.strip()} ({e})"
                        )

                    line = file.readline()
                print() # Necessary for displaying the progress bar. Without it, it will be overwritten.

        except (IOError, EnvironmentError) as e:
            logging.error(f"Could not open file '{filepath}': {e}")
            print(e)
            return None

    elif data is not None:
        data_lines = data.splitlines()
        data_length = len(data_lines)

        for line_number, line in enumerate(data_lines, start=1):
            last_percent = progress_bar(data_length, line_number, last_percent)
            try:
                if filters and not check_all_matches(line, filters):
                    continue
                entry = parser(line, request_pattern, date_pattern, date_keys)
                if entry:
                    requests.append(entry)
            except Exception as e:
                logging.warning(
                    f"{settings['type']} parse error at line {line_number}: {line.strip()} ({e})"
                )
        print() # Necessary for displaying the progress bar. Without it, it will be overwritten.

    else:
        logging.error(f"No filepath and empty data")

    return requests





def export_results(requests, output_path="output"):
    """
    Export parsed requests to both CSV and JSON in the current working directory.
    """
    if not requests:
        print("Nothing to export.")
        return

    # Extract just the base name to ensure files save in the current folder
    base_name = os.path.splitext(os.path.basename(output_path))[0]
    if not base_name:
        base_name = "output"

    # Export to JSON
    json_path = f"{base_name}.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(requests, f, indent=2, default=str)

    # Export to CSV
    csv_path = f"{base_name}.csv"
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        # Using the keys from the first dictionary as the CSV column headers
        writer = csv.DictWriter(f, fieldnames=requests[0].keys())
        writer.writeheader()
        writer.writerows(requests)

    print(f"Exported {len(requests)} records to both '{json_path}' and '{csv_path}'.")


def main():
    parser = argparse.ArgumentParser(description="Analyze server log files (nginx, apache2, auth)")
    parser.add_argument('--service', choices=['nginx', 'apache2', 'auth'], help='Type of log to analyze')
    parser.add_argument('--logfile', help='Path to the log file')
    parser.add_argument('--filter', required=False, default=None, help='String to filter log lines')
    parser.add_argument('--export', required=False, default=None, help='Base filename for export (creates both .json and .csv)')

    if len(sys.argv) == 1:
        logfile, service = start_wizard()
        filter_value = None
        export_value = None
    else:
        args = parser.parse_args()

        if not args.service or not args.logfile:
            parser.error('--service and --logfile are required unless you start the wizard without arguments')

        service = args.service
        logfile = args.logfile
        filter_value = args.filter
        export_value = args.export

    filters = []
    if filter_value:
        filters.append({
            'filter_pattern': filter_value,
            'is_casesensitive': True,
            'is_regex': False,
            'is_reverse': False
        })

    requests = get_requests(service, filepath=logfile, filters=filters)

    if requests:
        for req in requests:
            print(req)
    else:
        print("No requests found.")

    if export_value:
        export_results(requests, output_path=export_value)

# CLI entry point
if __name__ == '__main__':
    main()
