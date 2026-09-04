from .scanner import MomusScanner, Finding
from .claims import audit_claims, render_prompt, render_table, ClaimReport, ClaimFinding

__all__ = ["MomusScanner", "Finding", "audit_claims", "render_prompt", "render_table",
           "ClaimReport", "ClaimFinding", "main"]


def __getattr__(name):
    if name == "main":
        from .cli import main
        return main
    raise AttributeError(name)
