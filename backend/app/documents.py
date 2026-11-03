"""Upload validation and text extraction for PDF / DOCX resumes."""

from __future__ import annotations

import io
import zipfile

PDF = "application/pdf"
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
MAX_EXTRACTED_CHARS = 40_000


class DocumentError(ValueError):
    pass


def sniff_media_type(data: bytes, filename: str) -> str:
    """Decide the type from magic bytes, not from the client-supplied content type."""
    name = filename.lower()
    if data.startswith(b"%PDF-") and name.endswith(".pdf"):
        return PDF
    if data.startswith(b"PK\x03\x04") and name.endswith(".docx"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if "word/document.xml" in zf.namelist():
                    return DOCX
        except zipfile.BadZipFile:
            pass
    raise DocumentError("Only PDF or DOCX resumes are accepted")


def extract_text(data: bytes, media_type: str) -> str:
    if media_type == PDF:
        from pypdf import PdfReader

        try:
            reader = PdfReader(io.BytesIO(data))
            if len(reader.pages) > 10:
                raise DocumentError("Resume has more than 10 pages")
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
        except DocumentError:
            raise
        except Exception as exc:  # pypdf raises many types on malformed input
            raise DocumentError("Could not read PDF") from exc
    elif media_type == DOCX:
        from docx import Document

        try:
            doc = Document(io.BytesIO(data))
        except Exception as exc:
            raise DocumentError("Could not read DOCX") from exc
        text = "\n".join(p.text for p in doc.paragraphs)
    else:
        raise DocumentError(f"Unsupported media type {media_type}")
    text = text.replace("\x00", "").strip()
    if not text:
        raise DocumentError("No text found in document (scanned images are not supported)")
    return text[:MAX_EXTRACTED_CHARS]


def make_pdf(lines: list[str]) -> bytes:
    """Minimal single-page text PDF writer (used for samples, seed data and tests)."""

    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    body = "BT /F1 10 Tf 50 780 Td 13 TL\n" + "".join(f"({esc(line)}) Tj T*\n" for line in lines) + "ET"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        "/Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(body.encode('latin-1'))} >>\nstream\n{body}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{obj}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += "".join(f"{off:010d} 00000 n \n" for off in offsets).encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def make_docx(lines: list[str]) -> bytes:
    from docx import Document

    doc = Document()
    for line in lines:
        doc.add_paragraph(line)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
