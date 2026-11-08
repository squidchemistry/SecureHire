"""Finished analyses (derived, non-identifying data only)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import audit, repositories
from app.api.deps import current_user
from app.db import get_db
from app.models import User

router = APIRouter(prefix="/api/analyses", tags=["analyses"])


class AnalysisSummary(BaseModel):
    id: str
    run_id: str
    target_role: str
    match_score: float
    missing_skills: list[str]
    security_flags: int
    created_at: datetime


class AnalysisOut(AnalysisSummary):
    matched_skills: list[str]
    prep_plan: list[dict[str, Any]]
    questions: list[dict[str, Any]]
    summary: str


class AnalysisPage(BaseModel):
    items: list[AnalysisSummary]
    next_cursor: str | None


@router.get("", response_model=AnalysisPage)
def list_analyses(limit: int = Query(20, ge=1, le=50), cursor: str | None = None,
                  user: User = Depends(current_user), db: Session = Depends(get_db)) -> AnalysisPage:
    try:
        rows, nxt = repositories.list_analyses(db, user_id=user.id, limit=limit, cursor=cursor)
    except repositories.BadCursor:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor") from None
    return AnalysisPage(items=[AnalysisSummary.model_validate(r, from_attributes=True) for r in rows],
                        next_cursor=nxt)


@router.get("/{analysis_id}", response_model=AnalysisOut)
def get_analysis(analysis_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)) -> AnalysisOut:
    row = repositories.get_analysis(db, user_id=user.id, analysis_id=analysis_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    return AnalysisOut.model_validate(row, from_attributes=True)


@router.delete("/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def delete_analysis(analysis_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    row = repositories.get_analysis(db, user_id=user.id, analysis_id=analysis_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    db.delete(row)
    audit.record(db, event="analysis.delete", user_id=user.id, run_id=row.run_id, decision="allow")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
