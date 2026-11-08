"""The agent's tools.

Data flow is deliberately one-way from untrusted to trusted:

    resume bytes -> parse_resume (PII stripped, injection scanned)
                 -> extract_skills (closed taxonomy: canonical names only)
                 -> compare_to_jd / generate_* (see canonical names, never resume text)

Only `parse_resume` returns document text to the model, and it does so inside a
random, unforgeable boundary. Every tool reads its owner from `ToolContext`,
never from arguments, and every query goes through user-scoped repositories.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from app import documents, repositories
from app.agent.content import template_prep_plan, template_questions
from app.agent.registry import StrictInput, Tool, ToolContext, ToolError, ToolRegistry
from app.llm.base import LLMError
from app.security import injection, pii
from app.skills import category_of, extract_skills, is_known

log = logging.getLogger(__name__)

RESUME_PREVIEW_CHARS = 4_000


# --- schemas -------------------------------------------------------------------

class NoArgs(StrictInput):
    pass


class ParseResumeOut(BaseModel):
    text: str
    chars: int
    pii_redacted: dict[str, int]
    injection_flags: list[str]


class ExtractSkillsOut(BaseModel):
    skills: list[str]
    by_category: dict[str, list[str]]


class CompareOut(BaseModel):
    target_role: str
    jd_skills: list[str]
    matched: list[str]
    missing: list[str]
    extra: list[str]
    match_score: float
    jd_flags: list[str] = []


class FetchPastIn(StrictInput):
    limit: int = Field(default=5, ge=1, le=10)


class PastItem(BaseModel):
    target_role: str
    match_score: float
    missing_skills: list[str]
    created_at: str


class FetchPastOut(BaseModel):
    count: int
    recurring_gaps: list[str]
    previous: list[PastItem]


class PrepPlanIn(StrictInput):
    days: int | None = Field(default=None, ge=1, le=30)


class PlanDay(BaseModel):
    day: int = Field(ge=1, le=30)
    focus: str = Field(max_length=60)
    tasks: list[str] = Field(min_length=1, max_length=4)
    kind: str | None = None


class PrepPlanOut(BaseModel):
    days: int
    plan: list[PlanDay]
    source: Literal["llm", "template"]


class QuestionsIn(StrictInput):
    count: int | None = Field(default=None, ge=1, le=15)
    difficulty: Literal["junior", "mid", "senior", "mixed"] | None = None


class Question(BaseModel):
    skill: str = Field(max_length=60)
    question: str = Field(max_length=300)
    difficulty: str = Field(max_length=20)
    why: str = Field(max_length=120)


class QuestionsOut(BaseModel):
    questions: list[Question]
    source: Literal["llm", "template"]


# --- helpers -------------------------------------------------------------------

def _load_text(ctx: ToolContext, document_id: str | None, what: str) -> str:
    if not document_id:
        raise ToolError(f"No {what} was provided for this run.")
    with ctx.open_session() as s:
        doc = repositories.get_document(s, user_id=ctx.user_id, document_id=document_id)
        if doc is None:
            raise ToolError(f"The {what} is no longer available.")
        data, media_type = doc.content, doc.media_type
    if media_type == "text/plain":
        return data.decode("utf-8", errors="replace")[: ctx.settings.max_jd_chars]
    try:
        return documents.extract_text(data, media_type)
    except documents.DocumentError as exc:
        raise ToolError(str(exc)) from None


def _clean_untrusted(ctx: ToolContext, text: str, *, first_line_is_name: bool) -> tuple[str, dict[str, int], list[str]]:
    """PII-strip, scan and (optionally) redact untrusted text. Returns (text, pii_counts, flag_categories)."""
    red = pii.redact(text, first_line_is_name=first_line_is_name)
    flags = sorted({f.category for f in injection.scan(red.text)})
    out = red.text
    if flags and ctx.settings.injection_action == "redact":
        out = injection.redact_instructions(out)
    return out, red.counts, flags


def _comparison(ctx: ToolContext) -> dict[str, Any]:
    comp = ctx.artifacts.get("comparison")
    if not comp:
        raise ToolError("compare_to_jd must run first.")
    return comp


def _generate(ctx: ToolContext, system: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    """Ask the LLM for JSON. Returns None (-> template fallback) when unsupported or invalid."""
    if not ctx.llm.supports_generation:
        return None
    try:
        return ctx.llm.complete_json(system, json.dumps(payload))
    except LLMError as exc:
        log.warning("content generation failed, using template: %s", exc)
        return None


# --- tools ---------------------------------------------------------------------

def parse_resume(_: NoArgs, ctx: ToolContext) -> ParseResumeOut:
    raw = _load_text(ctx, ctx.resume_document_id, "resume")
    text, counts, flags = _clean_untrusted(ctx, raw, first_line_is_name=True)
    return ParseResumeOut(text=text, chars=len(text), pii_redacted=counts, injection_flags=flags)


def _render_resume(out: ParseResumeOut) -> dict[str, Any]:
    return {
        "resume": injection.wrap_untrusted(
            out.text[:RESUME_PREVIEW_CHARS], source="resume", flagged=bool(out.injection_flags)
        ),
        "pii_redacted": out.pii_redacted,
        "injection_flags": out.injection_flags,
    }


def extract_skills_tool(_: NoArgs, ctx: ToolContext) -> ExtractSkillsOut:
    resume = ctx.artifacts.get("resume")
    if not resume:
        raise ToolError("parse_resume must run first.")
    skills = extract_skills(resume["text"])
    by_cat: dict[str, list[str]] = {}
    for s in skills:
        by_cat.setdefault(category_of(s), []).append(s)
    return ExtractSkillsOut(skills=skills, by_category=by_cat)


def compare_to_jd(_: NoArgs, ctx: ToolContext) -> CompareOut:
    skills = ctx.artifacts.get("skills")
    if not skills:
        raise ToolError("extract_skills must run first.")
    jd_raw = _load_text(ctx, ctx.jd_document_id, "job description")
    jd_text, _, jd_flags = _clean_untrusted(ctx, jd_raw, first_line_is_name=False)
    jd_skills = extract_skills(jd_text)
    have = set(skills["skills"])
    matched = [s for s in jd_skills if s in have]
    missing = [s for s in jd_skills if s not in have]
    extra = [s for s in skills["skills"] if s not in set(jd_skills)]
    score = round(100.0 * len(matched) / len(jd_skills), 1) if jd_skills else 0.0
    return CompareOut(
        target_role=str(ctx.options.get("target_role", "Software Engineer")),
        jd_skills=jd_skills,
        matched=matched,
        missing=missing,
        extra=extra,
        match_score=score,
        jd_flags=jd_flags,
    )


def fetch_past_analyses(args: FetchPastIn, ctx: ToolContext) -> FetchPastOut:
    # Owner comes from the server-side context; the model cannot name another user.
    with ctx.open_session() as s:
        rows, _ = repositories.list_analyses(s, user_id=ctx.user_id, limit=args.limit)
        previous = [
            PastItem(
                target_role=r.target_role,
                match_score=r.match_score,
                missing_skills=[m for m in r.missing_skills if is_known(m)],
                created_at=r.created_at.isoformat(),
            )
            for r in rows
        ]
    tally: dict[str, int] = {}
    for p in previous:
        for m in p.missing_skills:
            tally[m] = tally.get(m, 0) + 1
    recurring = sorted((m for m, n in tally.items() if n >= 2), key=lambda m: (-tally[m], m))
    return FetchPastOut(count=len(previous), recurring_gaps=recurring, previous=previous)


_PLAN_SYSTEM = (
    "You write interview preparation plans. Input is JSON with canonical skill names. "
    'Reply with JSON: {"plan": [{"day": 1, "focus": "<one skill from the input or \'Mock interview\'>", '
    '"tasks": ["<concrete task>", ...]}]} with exactly `days` entries and at most 3 tasks per day. '
    "Prioritise recurring_gaps, then missing. End with a mock interview day when days > 1."
)


def generate_prep_plan(args: PrepPlanIn, ctx: ToolContext) -> PrepPlanOut:
    comp = _comparison(ctx)
    days = args.days or int(ctx.options.get("days", 7))
    recurring = (ctx.artifacts.get("history") or {}).get("recurring_gaps", [])
    allowed_focus = set(comp["missing"]) | set(comp["matched"]) | set(recurring) | {"Mock interview", "Review"}
    generated = _generate(ctx, _PLAN_SYSTEM, {
        "target_role": comp["target_role"],
        "days": days,
        "missing": comp["missing"],
        "matched": comp["matched"],
        "recurring_gaps": recurring,
    })
    if generated is not None:
        try:
            plan = [PlanDay.model_validate(d) for d in generated.get("plan", [])]
            if len(plan) == days and all(d.focus in allowed_focus for d in plan) and _clean_generated(
                [t for d in plan for t in d.tasks]
            ):
                return PrepPlanOut(days=days, plan=plan, source="llm")
        except (ValidationError, AttributeError, TypeError):
            pass
        log.info("LLM prep plan failed validation; using template")
    plan = [PlanDay.model_validate(d) for d in template_prep_plan(comp["missing"], comp["matched"], recurring, days)]
    return PrepPlanOut(days=days, plan=plan, source="template")


_QUESTIONS_SYSTEM = (
    "You write technical interview questions. Input is JSON with canonical skill names. "
    'Reply with JSON: {"questions": [{"skill": "<skill from input or \'Behavioural\'>", "question": "...", '
    '"difficulty": "<difficulty>", "why": "<one short reason>"}]} with exactly `count` questions. '
    "Favour missing skills; include at least one behavioural question."
)


def generate_questions(args: QuestionsIn, ctx: ToolContext) -> QuestionsOut:
    comp = _comparison(ctx)
    count = args.count or int(ctx.options.get("question_count", 8))
    difficulty = args.difficulty or str(ctx.options.get("difficulty", "mixed"))
    allowed = set(comp["missing"]) | set(comp["matched"]) | {"Behavioural"}
    generated = _generate(ctx, _QUESTIONS_SYSTEM, {
        "target_role": comp["target_role"],
        "count": count,
        "difficulty": difficulty,
        "missing": comp["missing"],
        "matched": comp["matched"],
    })
    if generated is not None:
        try:
            qs = [Question.model_validate(q) for q in generated.get("questions", [])]
            if qs and len(qs) <= count and all(q.skill in allowed for q in qs) and _clean_generated(
                [q.question for q in qs]
            ):
                return QuestionsOut(questions=qs, source="llm")
        except (ValidationError, AttributeError, TypeError):
            pass
        log.info("LLM questions failed validation; using template")
    qs = [Question.model_validate(q) for q in template_questions(comp["missing"], comp["matched"], count, difficulty)]
    return QuestionsOut(questions=qs, source="template")


def _clean_generated(texts: list[str]) -> bool:
    """Generated text must not carry PII or instruction-like content back to the user."""
    return not any(pii.contains_pii(t) or injection.scan(t) for t in texts)


# --- registry ------------------------------------------------------------------

def build_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(Tool(
        name="parse_resume",
        description="Extract the uploaded resume's text with personal data removed. Takes no arguments.",
        input_model=NoArgs,
        output_model=ParseResumeOut,
        fn=parse_resume,
        produces="resume",
        max_calls=1,
        render=_render_resume,
        summarize=lambda o: {"chars": o.chars, "pii_redacted": o.pii_redacted, "injection_flags": o.injection_flags},
    ))
    reg.register(Tool(
        name="extract_skills",
        description="Map the parsed resume onto the canonical skills taxonomy. Takes no arguments.",
        input_model=NoArgs,
        output_model=ExtractSkillsOut,
        fn=extract_skills_tool,
        produces="skills",
        requires=("resume",),
        max_calls=1,
        summarize=lambda o: {"skills": len(o.skills), "categories": sorted(o.by_category)},
    ))
    reg.register(Tool(
        name="compare_to_jd",
        description="Compare the extracted skills with the job description and compute a match score. No arguments.",
        input_model=NoArgs,
        output_model=CompareOut,
        fn=compare_to_jd,
        produces="comparison",
        requires=("skills",),
        max_calls=1,
        summarize=lambda o: {
            "match_score": o.match_score, "matched": len(o.matched), "missing": len(o.missing),
            "jd_flags": o.jd_flags,
        },
    ))
    reg.register(Tool(
        name="fetch_past_analyses",
        description="Fetch this user's previous analyses to find recurring skill gaps. Optional: limit (1-10).",
        input_model=FetchPastIn,
        output_model=FetchPastOut,
        fn=fetch_past_analyses,
        produces="history",
        requires=("comparison",),
        max_calls=1,
        summarize=lambda o: {"previous": o.count, "recurring_gaps": o.recurring_gaps},
    ))
    reg.register(Tool(
        name="generate_prep_plan",
        description="Create a day-by-day preparation plan from the skill gaps. Optional: days (1-30).",
        input_model=PrepPlanIn,
        output_model=PrepPlanOut,
        fn=generate_prep_plan,
        produces="prep_plan",
        requires=("comparison",),
        max_calls=2,
        summarize=lambda o: {"days": o.days, "source": o.source},
    ))
    reg.register(Tool(
        name="generate_questions",
        description="Create practice interview questions. Optional: count (1-15), difficulty.",
        input_model=QuestionsIn,
        output_model=QuestionsOut,
        fn=generate_questions,
        produces="questions",
        requires=("comparison",),
        max_calls=2,
        summarize=lambda o: {"questions": len(o.questions), "source": o.source},
    ))
    return reg

