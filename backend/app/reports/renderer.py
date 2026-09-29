"""HTML/PDF report rendering for a completed analysis (Stage 11).

Both formats render the exact same §7 contract dict `GET /api/analyses/{id}` returns
(plus a couple of report-only metadata fields - see `router.py`) through one Jinja2
template, so the report is a different *view* of the frozen JSON, never a second,
independently-computed summary of it. PDF is produced by rendering to HTML first and
feeding that to WeasyPrint, rather than building a separate PDF-specific layout - one
template to keep in sync with the contract instead of two.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(["html"]),
)

# Evidence strings and SNI/subject fields ultimately come from attacker-observable
# packet bytes (e.g. a STARTTLS-stripping finding's evidence is the literal leaked
# plaintext command) - autoescaping is load-bearing here, not a default left on by
# accident, since a captured payload could otherwise inject markup into the report.


def render_html(report_data: dict) -> str:
    return _env.get_template("report.html.j2").render(**report_data)


def render_pdf(report_data: dict) -> bytes:
    # Imported lazily: WeasyPrint pulls in native Pango/cairo/gdk-pixbuf libraries that
    # the JSON/HTML report paths don't need, and that aren't always installed (notably
    # on a bare Windows dev machine) - importing it eagerly would break `import
    # app.reports.renderer` (and everything that transitively imports it) in an
    # environment that only ever asks for the JSON or HTML report.
    from weasyprint import HTML

    html = render_html(report_data)
    return HTML(string=html, base_url=str(_TEMPLATES_DIR)).write_pdf()
