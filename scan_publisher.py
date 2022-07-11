#!/usr/bin/env python3

import json
import sys
from argparse import ArgumentParser
from urllib import request
import logging


logger = logging.getLogger('')
logging.basicConfig(level=logging.DEBUG, format='%(message)s')

ENDPOINT_URL = 'https://app.tromzo.com/webhook/%s/'

ALLOWED_SCANNERS = {
    'gitleaks',
    'semgrep',
}


def upload_results(args):
    data = json.loads(open(args.input_file).read())
    if args.scanner == 'semgrep':
        data = data['results']
    data = {
        'findings': data,
        'repo_name': args.repo_name,
        'pull_request_url':
            f'https://github.com/{args.repo_name}/pull/{args.pull_request}',
        'token': args.token,
        'organization_name': args.org_name,
    }
    url = ENDPOINT_URL % args.scanner

    data = json.dumps(data).encode()
    req = request.Request(url, data=data)
    resp = request.urlopen(req)  # nosec
    resp_text = resp.read()

    if resp_text == b'Done':
        logger.info('Upload success')
    else:
        logger.info('Upload failed')


def main():
    parser = ArgumentParser()
    parser.add_argument(
        '-r', '--repository', action='store', dest='repo_name',
        help='repository name, eg. MyCompany/repo1', required=True,
    )
    parser.add_argument(
        '-p', '--pull_request', action='store', dest='pull_request',
        help='pull request number, eg. 42', required=True,
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
    args = parser.parse_args(sys.argv[1:])
    if args.scanner not in ALLOWED_SCANNERS:
        logger.warning('Wrong scanner %s' % args.scanner)
        return
    upload_results(args)


if __name__ == '__main__':
    main()
