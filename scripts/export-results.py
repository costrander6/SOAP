from argparse import ArgumentParser
from datetime import datetime
import json
import os
import subprocess

from models import ResultsRequest

def get_repo_info() -> tuple:
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

    return (repo_name, branch_name, commit_hash)


def get_actionlint_results(timestamp: datetime) -> ResultsRequest | None:
    ACTIONLINT_FILE = 'actionlint-out.json'

    try:
        with open(ACTIONLINT_FILE, 'r') as f:
            data = json.load(f)
    except OSError:
        return None
    
    resultsRequest = ResultsRequest.model_validate(data)
    resultsRequest.timestamp = timestamp

    repo, branch, commit = get_repo_info()
    resultsRequest.source.repo = repo
    resultsRequest.source.branch = branch
    resultsRequest.source.commit = commit

    return resultsRequest


def get_poutine_results(): pass
def get_frizbee_results(): pass
def get_semgrep_results(): pass

def main():
    POUTINE_FILE = 'poutine-out.json'
    FRIZBEE_FILE = 'frizbee-out.json'
    SEMGREP_FILE = 'semgrep-out.json'
    RED = "\033[31m"
    RESET = "\033[0m"

    parser = ArgumentParser(description='A tool that sends the output from SOAP compatible scanners to the SOAP service')
    parser.add_argument('actionlint_timestamp', type=lambda s: datetime.fromisoformat(s))
    parser.add_argument('poutine_timestamp', type=lambda s: datetime.fromisoformat(s))
    parser.add_argument('frizbee_timestamp', type=lambda s: datetime.fromisoformat(s))
    parser.add_argument('semgrep_timestamp', type=lambda s: datetime.fromisoformat(s))
    args = parser.parse_args()

    actionlint_results = get_actionlint_results(args.actionlint_timestamp)
    poutine_results = get_poutine_results()
    frizbee_results = get_frizbee_results()
    semgrep_results = get_semgrep_results()

    if actionlint_results is None:
        print(f'{RED}ERROR: Failed to read actionlint results file{RESET}')

    print(actionlint_results)


if __name__ == '__main__':
    main()