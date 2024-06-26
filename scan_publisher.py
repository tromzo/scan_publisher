#!/usr/bin/env python3

import json
import sys
from argparse import ArgumentParser
from urllib import request
import logging


logger = logging.getLogger('')
logging.basicConfig(level=logging.DEBUG, format='%(message)s')

ENDPOINT_HOST = 'app.tromzo.com'
ENDPOINT_URL = 'https://%s/webhook/%s/'

ALLOWED_SCANNERS = {
    'gitleaks',
    'semgrep',
    'nessuscustom',
}


def upload_results(args):
    data = json.loads(open(args.input_file).read())
    if args.scanner == 'semgrep':
        data = data['results']
    data = {
        'findings': data,
        'repo_name': args.repo_name,
        'token': args.token,
        'organization_name': args.org_name,
    }
    if args.pull_request:
        pull_request_number = int(args.pull_request)
        data['pull_request_url'] = f'https://github.com/{args.repo_name}/pull/{pull_request_number}'

    if args.commit:
        data['commit'] = args.commit
        
    endpoint_host = args.endpoint or ENDPOINT_HOST

    url = ENDPOINT_URL % (endpoint_host, args.scanner)
    if 'tr.local' in endpoint_host:
        url = url.replace('https://', 'http://')

    data = json.dumps(data).encode()
    req = request.Request(url, data=data)
    resp = request.urlopen(req)  # nosec
    resp_text = resp.read()

    if resp_text == b'None':
        logger.info('Upload success')
    else:
        logger.info('Upload failed, details: %s' % resp_text)


def main():
    parser = ArgumentParser()
    parser.add_argument(
        '-r', '--repository', action='store', dest='repo_name',
        help='repository name, eg. MyCompany/repo1', required=False,
    )
    parser.add_argument(
        '-p', '--pull_request', action='store', dest='pull_request',
        help='pull request number, eg. 42', required=False,
    )
    parser.add_argument(
        '-c', '--commit', action='store', dest='commit',
        help='pull request commit hasth, eg af9926c88e0c310c', required=False,
    )
    parser.add_argument(
        '-o', '--organization', action='store', dest='org_name',
        help='organization name, eg. tromzo', required=True,
    )
    parser.add_argument(
        '-t', '--token', action='store', dest='token',
        help='your organization token', required=True,
    )
    parser.add_argument(
        '-f', '--file', action='store', dest='input_file',
        help='input file', required=True,
    )
    parser.add_argument(
        '-s', '--scanner', action='store', dest='scanner',
        help='scanner name, eg. gitleaks', required=True,
    )
    parser.add_argument(
        '-e', '--endpoint', action='store', dest='endpoint',
        help='endpoint host, eg. app.tromzo.com', required=False,
    )
    args = parser.parse_args(sys.argv[1:])
    if args.scanner not in ALLOWED_SCANNERS:
        logger.warning('Wrong scanner %s' % args.scanner)
        return
    upload_results(args)


if __name__ == '__main__':
    main()
