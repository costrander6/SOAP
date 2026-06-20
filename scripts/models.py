from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from enum import Enum

class SeverityLevel(Enum):
    UNCATEGORIZED = "UNCATEGORIZED"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Source(BaseModel):
    repo: str
    branch: str
    commit: str

class Finding(BaseModel):
    title: str
    description: str
    file: str
    line_start: int = Field(alias='lineStart')
    line_end: int = Field(alias='lineEnd')
    severity: Optional[SeverityLevel] = None

class ScanResult(BaseModel):
    workflow_run_id: Optional[str] = Field(default=None, alias='workflowRunId')
    scanner: str
    findings: list[Finding]

class CreateWorkflowRunRequest(BaseModel):
    repo: str
    branch: str
    commit: str
    timestamp: datetime