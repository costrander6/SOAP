from argparse import ArgumentParser
from datetime import datetime
import json
import os
import requests
import subprocess

from models import *

extra_values_to_severities = {"note": SeverityLevel.LOW, "info": SeverityLevel.LOW, "warning": SeverityLevel.MEDIUM,
                              "error": SeverityLevel.HIGH}

def get_repo_info() -> Source:
    repo_dir = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
    )
    repo_name = os.path.basename(repo_dir.decode("utf-8").strip())

    branch_name = os.environ.get("GITHUB_REF_NAME")
    if branch_name is None:
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
    if os.path.isdir(target):
        filename = os.path.basename(scanner_path)
        onlyfiles = [f for f in os.listdir(target) if os.path.isfile(os.path.join(target, f))]
        if filename in onlyfiles:
            return str(os.path.join(target, filename))
    return scanner_path

def map_string_to_severity_level(value: str) -> SeverityLevel:
    try:
        severity = SeverityLevel[value.upper()]
    except KeyError:
        if value.lower() in extra_values_to_severities:
            return extra_values_to_severities[value.lower()]
        else :
            return SeverityLevel.UNCATEGORIZED
    return severity

def get_actionlint_results() -> ScanResult | None:
    ACTIONLINT_FILE = 'actionlint-out.json'

    try:
        with open(ACTIONLINT_FILE, 'r') as f:
            data = json.load(f)
    except OSError:
        return None
    
    results_request = ScanResult.model_validate(data)

    for finding in results_request.findings:
        finding.severity = SeverityLevel.UNCATEGORIZED

    return results_request


def get_poutine_results(target: str) -> ScanResult | None: 
    POUTINE_FILE = 'poutine-out.json'

    try:
        with open(POUTINE_FILE, 'r') as f:
            data = json.load(f)
    except OSError:
        return None
    
    results_request = ScanResult(scanner="poutine", findings=[])
    
    rules = data['rules']
    findings = data['findings']
    for finding in findings:
        rule_id = finding['rule_id']
        rule = rules[rule_id]
        title = rule['title']
        description = rule['description']
        severity = rule['level']

        meta = finding['meta']
        line = meta['line']
        file = meta['path']
        
        results_request.findings.append(
            Finding(title=title, description=description, file=get_path(target, file), 
                    lineStart=line, lineEnd=line, severity=map_string_to_severity_level(severity))
        )

    return results_request
    

def get_frizbee_results(target: str) -> ScanResult | None: 
    FRIZBEE_FILE = 'frizbee-out.jsonl'

    json_lines = []
    try:
        with open(FRIZBEE_FILE, 'r') as f:
            for line in f:
                json_lines.append(json.loads(line))
    except OSError:
        return None
    
    results_request = ScanResult(scanner="frizbee", findings=[])
    
    for json_line in json_lines:
        for finding in json_line['findings']:
            title = 'Pin to commit SHA instead of tag'
            old = finding['old']
            new = finding['new']
            description = f'Replace "{old}" with "{new}"'
            file = finding['file']
            line = finding['line']

            results_request.findings.append(
                Finding(title=title, description=description, file=get_path(target, file), 
                        lineStart=line, lineEnd=line, severity=SeverityLevel.UNCATEGORIZED)
            )

    return results_request
    

def get_semgrep_results() -> ScanResult | None: 
    SEMGREP_FILE = 'semgrep-out.json'

    try:
        with open(SEMGREP_FILE, 'r') as f:
            data = json.load(f)
    except OSError:
        return None
    
    results_request = ScanResult(scanner='semgrep', findings=[])

    results = data['results']
    for result in results:
        file = result['path']
        lineStart = result['start']['line']
        lineEnd = result['end']['line']

        extra = result['extra']
        description = extra['message']
        severity = extra['severity']
        title = str(extra['metadata']['cwe'][0])

        title = title.split(': ', 1)[-1]


        results_request.findings.append(
            Finding(title=title, description=description, file=file, 
                    lineStart=lineStart, lineEnd=lineEnd, severity=map_string_to_severity_level(severity))
        )
    
    return results_request

def main():
    RED = "\033[31m"
    RESET = "\033[0m"

    parser = ArgumentParser(description='A tool that sends the output from SOAP compatible scanners to the SOAP service')
    parser.add_argument('api_key', type=str)
    parser.add_argument('base_url', type=str)
    parser.add_argument('timestamp', type=lambda s: datetime.fromisoformat(s))
    parser.add_argument('target', type=str)
    args = parser.parse_args()

    actionlint_results = get_actionlint_results()
    poutine_results = get_poutine_results(args.target)
    frizbee_results = get_frizbee_results(args.target)
    semgrep_results = get_semgrep_results()

    if actionlint_results is None:
        print(f'{RED}ERROR: Failed to read actionlint results file{RESET}')
    if poutine_results is None:
        print(f'{RED}ERROR: Failed to read poutine results file{RESET}')

    headers = {
        'Content-Type': 'application/json',
        'X-Api-Key': args.api_key
    }

    source = get_repo_info()

    create_workflow_run_request = CreateWorkflowRunRequest(repo=source.repo, branch=source.branch, commit=source.commit, 
                                                           timestamp=args.timestamp)
    
    response = requests.post(url=args.base_url + '/workflow-run', 
                             json=create_workflow_run_request.model_dump(mode='json'), headers=headers)
    response_data = response.json()
    workflow_run_id = response_data['id']
    scanner_result_url = args.base_url + '/scan-result'

    if actionlint_results is not None:
        actionlint_results.workflow_run_id = workflow_run_id
        requests.post(url=scanner_result_url, 
                      json=actionlint_results.model_dump(mode='json', by_alias=True), headers=headers)

    if poutine_results is not None:
        poutine_results.workflow_run_id = workflow_run_id
        requests.post(url=scanner_result_url, 
                      json=poutine_results.model_dump(mode='json', by_alias=True), headers=headers)

    if frizbee_results is not None:
        frizbee_results.workflow_run_id = workflow_run_id
        requests.post(url=scanner_result_url, 
                      json=frizbee_results.model_dump(mode='json', by_alias=True), headers=headers)

    if semgrep_results is not None:
        semgrep_results.workflow_run_id = workflow_run_id
        requests.post(url=scanner_result_url, 
                      json=semgrep_results.model_dump(mode='json', by_alias=True), headers=headers)



if __name__ == '__main__':
    main()