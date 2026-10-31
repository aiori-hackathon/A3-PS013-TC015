from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field

class InvestigationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default='', max_length=10000)
    notes: str = Field(default='', max_length=20000)
    triage_answers: list[str] = Field(default_factory=list, max_length=20)
    manual_baseline_minutes: float | None = Field(default=None, ge=0, le=100000)
    tool_assisted_minutes: float | None = Field(default=None, ge=0, le=100000)

class InvestigationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    notes: str | None = Field(default=None, max_length=20000)
    status: Literal['open', 'in_progress', 'closed'] | None = None
    triage_answers: list[str] | None = Field(default=None, max_length=20)
    manual_baseline_minutes: float | None = Field(default=None, ge=0, le=100000)
    tool_assisted_minutes: float | None = Field(default=None, ge=0, le=100000)

class AssociateIds(BaseModel):
    ids: list[str | int] = Field(min_length=1, max_length=500)
