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


def get_actionlint_results(timestamp: datetime) -> ResultsRequest | None:
    ACTIONLINT_FILE = 'actionlint-out.json'

    try:
        with open(ACTIONLINT_FILE, 'r') as f:
            data = json.load(f)
    except OSError:
        return None
    
    results_request = ResultsRequest.model_validate(data)
    results_request.timestamp = timestamp

    source = get_repo_info()
    results_request.source = source

    return results_request


def get_poutine_results(timestamp: datetime) -> ResultsRequest | None: 
    POUTINE_FILE = 'poutine-out.json'

    try:
        with open(POUTINE_FILE, 'r') as f:
            data = json.load(f)
    except OSError:
        return None
    
    results_request = ResultsRequest(scanner="poutine", timestamp=timestamp, source=get_repo_info(), findings=[])
    
    findings = data['findings']
    rules = data['rules']

    for finding in findings:
        rule_id = finding['rule_id']
        rule = rules[rule_id]
        title = rule['title']
        description = rule['description']

        meta = finding['meta']
        line = meta['line']
        file = meta['path']
        
        results_request.findings.append(
            Finding(title=title, description=description, file=file, lineStart=line, lineEnd=line)
        )

    return results_request
    

def get_frizbee_results(timestamp: datetime) -> ResultsRequest | None: 
    FRIZBEE_FILE = 'frizbee-out.jsonl'

    results = []

    try:
        with open(FRIZBEE_FILE, 'r') as f:
            for line in f:
                results.append(json.loads(line))
    except OSError:
        return None
    
    results_request = ResultsRequest(scanner="frizbee", timestamp=timestamp, source=get_repo_info(), findings=[])
    
    for findings in results:
        for finding in findings['findings']:
            title = 'Pin to commit SHA instead of tag'
            old = finding['old']
            new = finding['new']
            description = f'Replace "{old}" with "{new}"'
            file = finding['file']
            line = finding['line']

            results_request.findings.append(
                Finding(title=title, description=description, file=file, lineStart=line, lineEnd=line)
            )

    return results_request
    

def get_semgrep_results(): 
    SEMGREP_FILE = 'semgrep-out.json'
    

def main():
    RED = "\033[31m"
    RESET = "\033[0m"

    parser = ArgumentParser(description='A tool that sends the output from SOAP compatible scanners to the SOAP service')
    parser.add_argument('actionlint_timestamp', type=lambda s: datetime.fromisoformat(s))
    parser.add_argument('poutine_timestamp', type=lambda s: datetime.fromisoformat(s))
    parser.add_argument('frizbee_timestamp', type=lambda s: datetime.fromisoformat(s))
    parser.add_argument('semgrep_timestamp', type=lambda s: datetime.fromisoformat(s))
    args = parser.parse_args()

    actionlint_results = get_actionlint_results(args.actionlint_timestamp)
    poutine_results = get_poutine_results(args.poutine_timestamp)
    frizbee_results = get_frizbee_results(args.frizbee_timestamp)
    semgrep_results = get_semgrep_results()

    if actionlint_results is None:
        print(f'{RED}ERROR: Failed to read actionlint results file{RESET}')
    if poutine_results is None:
        print(f'{RED}ERROR: Failed to read poutine results file{RESET}')

    print(frizbee_results)


if __name__ == '__main__':
    main()