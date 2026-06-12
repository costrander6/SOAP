from argparse import ArgumentParser
from datetime import datetime
import json
import os
import subprocess

from models import Finding, ResultsRequest, Source

def get_repo_info() -> Source:
    repo_dir = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
    )
    repo_name = os.path.basename(repo_dir.decode("utf-8").strip())

    branch = subprocess.check_output(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"], stderr=subprocess.DEVNULL
    )
    branch_name = branch.decode("utf-8").strip()

    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
    )
    commit_hash = commit.decode("utf-8").strip()

    return Source(repo=repo_name, branch=branch_name, commit=commit_hash)

def get_path(target: str, scanner_path: str) -> str:
    if target == '.github/workflows':
        return scanner_path
    if os.path.isfile(target):
        return target
    if os.path.isdir(target):
        filename = os.path.basename(scanner_path)
        return str(os.path.join(target, filename))
    return scanner_path

def get_actionlint_results(timestamp: datetime) -> ResultsRequest | None:
    ACTIONLINT_FILE = 'actionlint-out.json'

    try:
        with open(ACTIONLINT_FILE, 'r') as f:
            data = json.load(f)
    except OSError:
        return None
    
    results_request = ResultsRequest.model_validate(data)
    results_request.timestamp = timestamp
    results_request.source = get_repo_info()

    return results_request


def get_poutine_results(timestamp: datetime, target: str) -> ResultsRequest | None: 
    POUTINE_FILE = 'poutine-out.json'

    try:
        with open(POUTINE_FILE, 'r') as f:
            data = json.load(f)
    except OSError:
        return None
    
    results_request = ResultsRequest(scanner="poutine", timestamp=timestamp, source=get_repo_info(), findings=[])
    
    rules = data['rules']
    findings = data['findings']
    for finding in findings:
        rule_id = finding['rule_id']
        rule = rules[rule_id]
        title = rule['title']
        description = rule['description']

        meta = finding['meta']
        line = meta['line']
        file = meta['path']
        
        results_request.findings.append(
            Finding(title=title, description=description, file=get_path(target, file), lineStart=line, lineEnd=line)
        )

    return results_request
    

def get_frizbee_results(timestamp: datetime, target: str) -> ResultsRequest | None: 
    FRIZBEE_FILE = 'frizbee-out.jsonl'

    json_lines = []
    try:
        with open(FRIZBEE_FILE, 'r') as f:
            for line in f:
                json_lines.append(json.loads(line))
    except OSError:
        return None
    
    results_request = ResultsRequest(scanner="frizbee", timestamp=timestamp, source=get_repo_info(), findings=[])
    
    for json_line in json_lines:
        for finding in json_line['findings']:
            title = 'Pin to commit SHA instead of tag'
            old = finding['old']
            new = finding['new']
            description = f'Replace "{old}" with "{new}"'
            file = finding['file']
            line = finding['line']

            results_request.findings.append(
                Finding(title=title, description=description, file=get_path(target, file), lineStart=line, lineEnd=line)
            )

    return results_request
    

def get_semgrep_results(timestamp: datetime) -> ResultsRequest | None: 
    SEMGREP_FILE = 'semgrep-out.json'

    try:
        with open(SEMGREP_FILE, 'r') as f:
            data = json.load(f)
    except OSError:
        return None
    
    results_request = ResultsRequest(scanner="semgrep", timestamp=timestamp, source=get_repo_info(), findings=[])

    results = data['results']
    for result in results:
        file = result['path']
        lineStart = result['start']['line']
        lineEnd = result['end']['line']

        extra = result['extra']
        description = extra['message']
        title = str(extra['metadata']['cwe'][0])

        title = title.split(': ', 1)[-1]


        results_request.findings.append(
            Finding(title=title, description=description, file=file, lineStart=lineStart, lineEnd=lineEnd)
        )
    
    return results_request
    

def main():
    RED = "\033[31m"
    RESET = "\033[0m"

    parser = ArgumentParser(description='A tool that sends the output from SOAP compatible scanners to the SOAP service')
    parser.add_argument('actionlint_timestamp', type=lambda s: datetime.fromisoformat(s))
    parser.add_argument('poutine_timestamp', type=lambda s: datetime.fromisoformat(s))
    parser.add_argument('target', type=str)
    parser.add_argument('-f', '--frizbee-timestamp', type=lambda s: datetime.fromisoformat(s))
    parser.add_argument('-s', '--semgrep-timestamp', type=lambda s: datetime.fromisoformat(s))
    args = parser.parse_args()

    actionlint_results = get_actionlint_results(args.actionlint_timestamp)
    poutine_results = get_poutine_results(args.poutine_timestamp, args.target)
    frizbee_results = None if args.frizbee_timestamp is None else get_frizbee_results(args.frizbee_timestamp, args.target)
    semgrep_results = None if args.semgrep_timestamp is None else get_semgrep_results(args.semgrep_timestamp)

    if actionlint_results is None:
        print(f'{RED}ERROR: Failed to read actionlint results file{RESET}')
    if poutine_results is None:
        print(f'{RED}ERROR: Failed to read poutine results file{RESET}')

    #TODO: remove print statements when the script sends the results to the SOAP service
    print('------------------actionlint------------------')
    print(actionlint_results)
    print('-------------------poutine-------------------')
    print(poutine_results)
    print('-------------------frizbee-------------------')
    print(frizbee_results)
    print('-------------------semgrep-------------------')
    print(semgrep_results)


if __name__ == '__main__':
    main()