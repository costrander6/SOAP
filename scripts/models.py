from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class Source(BaseModel):
    repo: Optional[str] = None
    branch: Optional[str] = None
    commit: Optional[str] = None

class Finding(BaseModel):
    title: str
    description: str
    file: str
    line_start: int = Field(alias='lineStart')
    line_end: int = Field(alias='lineEnd')

class ResultsRequest(BaseModel):
    scanner: str
    timestamp: Optional[datetime] = None
    source: Source = Field(default_factory=Source)
    findings: list[Finding]