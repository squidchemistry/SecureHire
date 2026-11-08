"""Deterministic content templates.

Used when the LLM cannot generate content (the mock) and as the fallback when
a real model returns output that fails validation. Inputs are canonical skill
names from the closed taxonomy only.
"""

from __future__ import annotations

from app.skills import category_of

_QUESTION_BANK: dict[str, list[str]] = {
    "language": [
        "Walk me through how memory is managed in {skill}. What trade-offs does that create?",
        "What {skill} feature do you reach for most, and when have you seen it misused?",
        "How would you structure a medium-sized {skill} codebase so it stays testable?",
    ],
    "framework": [
        "How does {skill} handle a request end-to-end? Where would you add authentication?",
        "Describe a performance problem you would expect in a {skill} application and how you'd find it.",
        "When would you choose not to use {skill}?",
    ],
    "concept": [
        "Explain {skill} to a new teammate, then describe a case where it went wrong.",
        "Design a small service that relies on {skill}. What are the failure modes?",
    ],
    "data": [
        "How would you model and index data in {skill} for a read-heavy workload?",
        "What consistency guarantees does {skill} give you, and how do they affect your design?",
    ],
    "cloud": [
        "How would you deploy a stateless API on {skill} with zero-downtime releases?",
        "Which {skill} services would you use to keep secrets out of your code?",
    ],
    "devops": [
        "Describe a production incident involving {skill} and how you would debug it.",
        "How would you introduce {skill} to a team that has never used it?",
    ],
    "ml": [
        "How do you evaluate a system built on {skill} before shipping it?",
        "What are the main ways a {skill} system fails in production, and how do you monitor for them?",
    ],
    "security": [
        "What are the most common {skill} mistakes you've seen in code review?",
        "How would you threat-model a feature that depends on {skill}?",
    ],
    "practice": [
        "How do you apply {skill} when deadlines are tight?",
        "Give an example of {skill} catching a problem early.",
    ],
    "soft": [
        "Tell me about a time {skill} made the difference on a project.",
        "Describe a disagreement where {skill} helped reach a decision.",
    ],
}

_BEHAVIOURAL = [
    "Tell me about the project you are most proud of. What would you change today?",
    "Describe a time you had to learn a technology quickly to deliver.",
    "How do you handle feedback in code review that you disagree with?",
]

_TASKS: dict[str, list[str]] = {
    "language": ["Work through 3 practice problems in {skill}", "Read the official {skill} style guide"],
    "framework": ["Build a small CRUD service with {skill}", "Read the {skill} docs on testing and deployment"],
    "concept": ["Write a one-page explainer on {skill}", "Sketch a design that uses {skill} and list its failure modes"],
    "data": ["Model a schema in {skill} and benchmark two query patterns", "Review {skill} indexing and transactions"],
    "cloud": ["Deploy a hello-world service on {skill}", "Review {skill} IAM and secrets management"],
    "devops": ["Set up {skill} for a sample project", "Debug a deliberately broken {skill} setup"],
    "ml": ["Reproduce a small {skill} tutorial end-to-end", "Write down how you would evaluate a {skill} system"],
    "security": ["Review OWASP guidance related to {skill}", "Audit a sample app for {skill} issues"],
    "practice": ["Apply {skill} to a past project of yours", "Prepare a STAR story involving {skill}"],
    "soft": ["Prepare two STAR stories showing {skill}", "Practise them aloud with a timer"],
}


def template_prep_plan(missing: list[str], matched: list[str], recurring: list[str], days: int) -> list[dict]:
    """Prioritise recurring gaps, then other missing skills, then refreshers on matched skills."""
    ordered: list[str] = []
    for s in [*recurring, *missing, *matched]:
        if s not in ordered:
            ordered.append(s)
    plan = []
    for day in range(1, days + 1):
        if day == days and days > 1:
            plan.append({
                "day": day,
                "focus": "Mock interview",
                "tasks": ["Run a timed mock interview with the generated questions", "Review weak answers"],
            })
            continue
        if not ordered:
            plan.append({"day": day, "focus": "Review", "tasks": ["Review your resume projects in depth"]})
            continue
        skill = ordered[(day - 1) % len(ordered)]
        kind = "refresh" if skill in matched and skill not in missing else "learn"
        tasks = [t.format(skill=skill) for t in _TASKS.get(category_of(skill), _TASKS["practice"])]
        plan.append({"day": day, "focus": skill, "tasks": tasks, "kind": kind})
    return plan


def template_questions(missing: list[str], matched: list[str], count: int, difficulty: str) -> list[dict]:
    questions: list[dict] = []
    pool = [(s, "gap") for s in missing] + [(s, "strength") for s in matched]
    round_ = 0
    while len(questions) < count and pool and round_ < 3:
        for skill, why in pool:
            bank = _QUESTION_BANK.get(category_of(skill), _QUESTION_BANK["concept"])
            if round_ < len(bank):
                questions.append({
                    "skill": skill,
                    "question": bank[round_].format(skill=skill),
                    "difficulty": difficulty,
                    "why": "Covers a gap in your resume" if why == "gap" else "Probes a claimed strength",
                })
            if len(questions) >= count:
                break
        round_ += 1
    for q in _BEHAVIOURAL:
        if len(questions) >= count:
            break
        questions.append({"skill": "Behavioural", "question": q, "difficulty": difficulty, "why": "Behavioural"})
    return questions[:count]
