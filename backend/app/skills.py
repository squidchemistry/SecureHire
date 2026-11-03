"""Closed skills taxonomy and matcher.

Skill extraction is deterministic on purpose: downstream tools (and the LLM
calls they make) receive only canonical names from this list, never free text
from the resume, which removes a whole class of injection paths.
"""

from __future__ import annotations

import re

# canonical name -> (category, aliases)
TAXONOMY: dict[str, tuple[str, tuple[str, ...]]] = {
    # languages
    "Python": ("language", ("python", "python3")),
    "Java": ("language", ("java",)),
    "JavaScript": ("language", ("javascript", "js", "ecmascript")),
    "TypeScript": ("language", ("typescript",)),
    "Go": ("language", ("golang",)),
    "Rust": ("language", ("rust",)),
    "C++": ("language", ("c++", "cpp")),
    "C#": ("language", ("c#", "csharp")),
    "Kotlin": ("language", ("kotlin",)),
    "SQL": ("language", ("sql",)),
    "Bash": ("language", ("bash", "shell scripting")),
    # backend / frameworks
    "FastAPI": ("framework", ("fastapi",)),
    "Django": ("framework", ("django",)),
    "Flask": ("framework", ("flask",)),
    "Spring Boot": ("framework", ("spring boot", "springboot")),
    "Node.js": ("framework", ("node.js", "nodejs", "node")),
    "Express": ("framework", ("express.js", "expressjs")),
    "React": ("framework", ("react", "react.js", "reactjs")),
    "Next.js": ("framework", ("next.js", "nextjs")),
    "Vue": ("framework", ("vue", "vue.js")),
    "Pydantic": ("framework", ("pydantic",)),
    "REST APIs": ("concept", ("restful", "rest api", "rest apis")),
    "GraphQL": ("concept", ("graphql",)),
    "gRPC": ("concept", ("grpc",)),
    "Microservices": ("concept", ("microservices", "microservice")),
    "System Design": ("concept", ("system design", "distributed systems")),
    "Data Structures & Algorithms": ("concept", ("data structures", "algorithms", "dsa")),
    # data
    "PostgreSQL": ("data", ("postgresql", "postgres")),
    "MySQL": ("data", ("mysql",)),
    "MongoDB": ("data", ("mongodb", "mongo")),
    "Redis": ("data", ("redis",)),
    "Kafka": ("data", ("kafka",)),
    "RabbitMQ": ("data", ("rabbitmq",)),
    "Elasticsearch": ("data", ("elasticsearch", "opensearch")),
    "Pandas": ("data", ("pandas",)),
    "Spark": ("data", ("spark", "pyspark")),
    "Airflow": ("data", ("airflow",)),
    # cloud / devops
    "AWS": ("cloud", ("aws", "amazon web services", "ec2", "s3", "lambda")),
    "GCP": ("cloud", ("gcp", "google cloud")),
    "Azure": ("cloud", ("azure",)),
    "Docker": ("devops", ("docker", "containers", "containerization")),
    "Kubernetes": ("devops", ("kubernetes", "k8s")),
    "Terraform": ("devops", ("terraform",)),
    "CI/CD": ("devops", ("ci/cd", "github actions", "jenkins", "gitlab ci", "continuous integration")),
    "Linux": ("devops", ("linux", "unix")),
    "Observability": ("devops", ("prometheus", "grafana", "opentelemetry", "observability", "monitoring")),
    "Git": ("devops", ("git",)),
    # ML / AI
    "Machine Learning": ("ml", ("machine learning", "ml", "scikit-learn", "sklearn")),
    "Deep Learning": ("ml", ("deep learning", "neural networks")),
    "PyTorch": ("ml", ("pytorch", "torch")),
    "TensorFlow": ("ml", ("tensorflow", "keras")),
    "NLP": ("ml", ("nlp", "natural language processing")),
    "LLMs": ("ml", ("llm", "llms", "large language models", "gpt", "groq", "openai")),
    "RAG": ("ml", ("rag", "retrieval augmented generation", "retrieval-augmented generation")),
    "Vector Databases": ("ml", ("vector database", "vector databases", "pgvector", "faiss", "pinecone")),
    "Prompt Engineering": ("ml", ("prompt engineering",)),
    # security
    "Application Security": ("security", ("application security", "appsec", "owasp", "secure coding")),
    "Authentication": ("security", ("oauth", "oauth2", "jwt", "authentication", "sso")),
    "Cryptography": ("security", ("cryptography", "encryption", "tls")),
    # practices
    "Testing": ("practice", ("pytest", "unit testing", "junit", "jest", "testing", "tdd")),
    "Agile": ("practice", ("agile", "scrum", "kanban")),
    "Code Review": ("practice", ("code review", "code reviews")),
    # soft skills
    "Communication": ("soft", ("communication", "stakeholder")),
    "Leadership": ("soft", ("leadership", "mentoring", "mentored", "led a team")),
}

# "Go" is too common an English word; only match it as a capitalised token
# followed by a typical context word.
_GO_CONTEXT = re.compile(r"\bGo\b(?=\s*(?:,|/|\)|lang|developer|services?|microservices|programming))")


def _compile() -> list[tuple[str, re.Pattern[str]]]:
    compiled = []
    for canonical, (_, aliases) in TAXONOMY.items():
        alts = "|".join(re.escape(a) for a in sorted(aliases, key=len, reverse=True))
        compiled.append((canonical, re.compile(rf"(?<![\w+#.])(?:{alts})(?![\w+#])", re.I)))
    return compiled


_COMPILED = _compile()


def extract_skills(text: str) -> list[str]:
    found = {canonical for canonical, pattern in _COMPILED if pattern.search(text)}
    if _GO_CONTEXT.search(text):
        found.add("Go")
    return sorted(found, key=lambda s: (category_of(s), s))


def category_of(skill: str) -> str:
    return TAXONOMY.get(skill, ("other", ()))[0]


def is_known(skill: str) -> bool:
    return skill in TAXONOMY
