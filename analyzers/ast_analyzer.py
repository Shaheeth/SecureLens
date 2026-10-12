"""
Custom Python AST analyzer.

IMPORTANT: `ast.parse()` only builds a syntax tree from source text. It does
NOT execute, import, or evaluate any code. This module never calls
`exec`, `eval`, `compile(..., 'exec')`, or `importlib` on user-supplied
source — it performs pure static structural analysis.

This complements Semgrep/Bandit with hand-written pattern detectors that:
  * catch patterns Semgrep's default rulesets may miss (e.g. f-string SQL
    building, string-concatenated SQL from GET-like sources),
  * give us full control over confidence scoring and CWE/OWASP mapping,
  * work even in environments where semgrep/bandit binaries are unavailable.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from backend.models import Finding, Severity, VulnCategory, CWE_OWASP_MAP

# --- keyword heuristics -----------------------------------------------------

_SQL_KEYWORDS = re.compile(r"\b(select|insert|update|delete|drop|union)\b", re.IGNORECASE)
_SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
_SECRET_VALUE_MIN_LEN = 6
_DANGEROUS_SHELL_FUNCS = {"os.system", "os.popen", "subprocess.call", "subprocess.run",
                           "subprocess.Popen", "subprocess.check_output", "commands.getoutput"}
_WEAK_HASHES = {"md5", "sha1"}
_INSECURE_RANDOM_MODULES = {"random"}
_DESERIALIZATION_FUNCS = {"pickle.load", "pickle.loads", "yaml.load", "marshal.loads",
                           "shelve.open"}
_XSS_TEMPLATE_FUNCS = {"render_template_string", "mark_safe", "Markup"}
_SSRF_FUNCS = {"requests.get", "requests.post", "requests.put", "requests.delete",
               "urllib.request.urlopen", "urlopen", "httpx.get", "httpx.post"}
_PATH_FUNCS = {"open", "os.remove", "os.rename", "shutil.copy", "shutil.move"}


def _dotted_name(node: ast.AST) -> str:
    """Reconstruct a dotted call name, e.g. os.system(...) -> 'os.system'."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _source_segment(source_lines: list[str], node: ast.AST) -> str:
    try:
        start = node.lineno - 1
        end = getattr(node, "end_lineno", node.lineno) - 1
        return "\n".join(source_lines[start:end + 1]).strip()[:400]
    except Exception:
        return ""


@dataclass
class _Ctx:
    file_path: str
    source_lines: list[str]
    findings: list


class SecurityASTVisitor(ast.NodeVisitor):
    """Walks the AST once, dispatching to focused pattern checks."""

    def __init__(self, ctx: _Ctx):
        self.ctx = ctx
        self._assigned_string_vars: dict[str, str] = {}

    # -- helpers --------------------------------------------------------
    def _add(self, node, category, severity, confidence, description, remediation):
        mapping = CWE_OWASP_MAP.get(category, {"cwe": [], "owasp": []})
        self.ctx.findings.append(Finding(
            source_tool="ast",
            category=category,
            severity=severity,
            confidence=confidence,
            file_path=self.ctx.file_path,
            line_start=getattr(node, "lineno", 0),
            line_end=getattr(node, "end_lineno", getattr(node, "lineno", 0)),
            evidence=_source_segment(self.ctx.source_lines, node),
            description=description,
            impact="",
            cwe_ids=mapping["cwe"],
            owasp_ids=mapping["owasp"],
            remediation=remediation,
        ))

    # -- visitors ---------------------------------------------------------
    def visit_Assign(self, node: ast.Assign):
        # Track simple string literal assignments for hardcoded-secret detection
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._check_hardcoded_secret(target.id, node.value.value, node)
        self.generic_visit(node)

    def _check_hardcoded_secret(self, var_name: str, value: str, node: ast.AST):
        if _SECRET_KEY_PATTERN.search(var_name) and len(value) >= _SECRET_VALUE_MIN_LEN:
            # Skip obvious placeholders
            if value.lower() in {"changeme", "your_password_here", "xxxxxx", "todo", ""}:
                return
            self._add(
                node, VulnCategory.HARDCODED_SECRET, Severity.HIGH, 0.75,
                f"Variable '{var_name}' appears to hold a hardcoded credential or secret.",
                "Move secrets to environment variables or a secrets manager "
                "(e.g. Vault, AWS Secrets Manager); never commit them to source control.",
            )

    def visit_BinOp(self, node: ast.BinOp):
        # String concatenation / % formatting that mixes an SQL keyword with a variable
        if isinstance(node.op, (ast.Add, ast.Mod)):
            text = ast.unparse(node) if hasattr(ast, "unparse") else ""
            if _SQL_KEYWORDS.search(text) and self._contains_name(node):
                self._add(
                    node, VulnCategory.SQL_INJECTION, Severity.CRITICAL, 0.7,
                    "SQL query appears to be built via string concatenation/formatting "
                    "with a non-constant value, risking SQL injection.",
                    "Use parameterized queries / prepared statements "
                    "(e.g. cursor.execute(query, params)) instead of string building.",
                )
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        # f-strings: f"SELECT * FROM users WHERE id={user_id}"
        text = "".join(
            v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else ""
            for v in node.values
        )
        has_expr = any(isinstance(v, ast.FormattedValue) for v in node.values)
        if _SQL_KEYWORDS.search(text) and has_expr:
            self._add(
                node, VulnCategory.SQL_INJECTION, Severity.CRITICAL, 0.75,
                "SQL query built using an f-string with interpolated values — "
                "classic SQL injection pattern.",
                "Use parameterized queries instead of f-string interpolation for SQL.",
            )
        if re.search(r"<[a-zA-Z]+", text) and has_expr:
            self._add(
                node, VulnCategory.XSS, Severity.MEDIUM, 0.5,
                "HTML appears to be built via f-string interpolation without "
                "apparent escaping, which can lead to XSS if the value is user-controlled.",
                "Use an auto-escaping template engine (Jinja2 autoescape=True) "
                "or explicitly escape output with markupsafe.escape().",
            )
        self.generic_visit(node)

    def _contains_name(self, node: ast.AST) -> bool:
        return any(isinstance(n, ast.Name) for n in ast.walk(node))

    def visit_Call(self, node: ast.Call):
        dotted = _dotted_name(node.func)
        func_name = dotted.split(".")[-1]

        # Command injection: os.system/subprocess with shell=True or f-string/concat args
        if dotted in _DANGEROUS_SHELL_FUNCS or func_name in {"system", "popen"}:
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            dynamic_arg = any(
                isinstance(a, (ast.JoinedStr, ast.BinOp)) or
                (isinstance(a, ast.Name))
                for a in node.args
            )
            if shell_true or dynamic_arg or dotted in {"os.system", "os.popen"}:
                self._add(
                    node, VulnCategory.COMMAND_INJECTION, Severity.CRITICAL, 0.7,
                    f"Call to '{dotted}' may execute a shell command built from "
                    "untrusted/dynamic input.",
                    "Avoid shell=True; pass arguments as a list to subprocess.run() "
                    "and validate/allow-list any user-supplied values.",
                )

        # Insecure deserialization
        if dotted in _DESERIALIZATION_FUNCS:
            self._add(
                node, VulnCategory.INSECURE_DESERIALIZATION, Severity.CRITICAL, 0.8,
                f"'{dotted}' can execute arbitrary code when deserializing "
                "untrusted data.",
                "Use safe alternatives (json, yaml.safe_load) or cryptographically "
                "sign/verify serialized data before loading it.",
            )

        # Weak crypto (hashlib.md5 / hashlib.sha1)
        if dotted in {"hashlib.md5", "hashlib.sha1"} or func_name in _WEAK_HASHES:
            self._add(
                node, VulnCategory.WEAK_CRYPTO, Severity.MEDIUM, 0.75,
                f"Use of weak hash algorithm ('{func_name}') is unsuitable for "
                "security-sensitive purposes (e.g. password storage).",
                "Use bcrypt/argon2/scrypt for password hashing, or SHA-256+ "
                "for general integrity checks.",
            )

        # Insecure randomness for security-relevant use (heuristic: var name hints)
        if dotted.startswith("random.") and func_name in {"random", "randint", "choice", "randrange"}:
            self._add(
                node, VulnCategory.INSECURE_RANDOMNESS, Severity.MEDIUM, 0.5,
                f"'{dotted}' uses a non-cryptographic PRNG; unsafe for tokens, "
                "passwords, or session IDs.",
                "Use the 'secrets' module (e.g. secrets.token_urlsafe()) for "
                "any security-sensitive randomness.",
            )

        # SSRF: requests/urllib calls with a non-constant URL argument
        if dotted in _SSRF_FUNCS and node.args:
            first_arg = node.args[0]
            if not isinstance(first_arg, ast.Constant):
                self._add(
                    node, VulnCategory.SSRF, Severity.HIGH, 0.55,
                    f"'{dotted}' is called with a non-constant URL, which may allow "
                    "SSRF if the URL is influenced by user input.",
                    "Validate/allow-list destination hosts, block requests to "
                    "internal/link-local addresses, and avoid forwarding raw user URLs.",
                )

        # Path traversal: file ops with a non-constant path built from concatenation
        if dotted in _PATH_FUNCS or func_name in {"open"}:
            if node.args and isinstance(node.args[0], (ast.BinOp, ast.JoinedStr)):
                self._add(
                    node, VulnCategory.PATH_TRAVERSAL, Severity.HIGH, 0.55,
                    f"'{func_name}' is called with a dynamically built path, which "
                    "may allow path traversal if it includes user input.",
                    "Resolve and validate paths against an allow-listed base "
                    "directory (e.g. os.path.realpath + startswith check) before use.",
                )

        # Auth weakness: Flask debug=True, hardcoded 'if password == ...':
        if func_name == "run" and any(
            kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        ):
            self._add(
                node, VulnCategory.AUTH_WEAKNESS, Severity.HIGH, 0.7,
                "Application is run with debug=True, which can expose an "
                "interactive debugger/RCE console in production.",
                "Disable debug mode in production; drive it from an environment "
                "variable that defaults to False.",
            )

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        # Naive password comparison: `if password == "admin123":`
        for side in [node.left, *node.comparators]:
            if isinstance(side, ast.Name) and _SECRET_KEY_PATTERN.search(side.id):
                other = node.comparators[0] if side is node.left else node.left
                if isinstance(other, ast.Constant) and isinstance(other.value, str):
                    self._add(
                        node, VulnCategory.AUTH_WEAKNESS, Severity.HIGH, 0.6,
                        "Credential appears to be compared against a hardcoded "
                        "constant using '==', which is also vulnerable to timing "
                        "attacks and implies a hardcoded credential.",
                        "Use a constant-time comparison (hmac.compare_digest) "
                        "against a securely hashed/stored credential, never a "
                        "hardcoded plaintext value.",
                    )
        self.generic_visit(node)


def analyze_source(file_path: str, source: str) -> list[Finding]:
    """
    Parse `source` (never executed) and run structural security checks.
    Returns [] with a descriptive finding-free result on a SyntaxError,
    since malformed files can't be meaningfully analyzed structurally
    (Semgrep/Bandit may still surface issues via regex-based rules).
    """
    findings: list = []
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        return [Finding(
            source_tool="ast",
            category=VulnCategory.OTHER,
            severity=Severity.INFO,
            confidence=1.0,
            file_path=file_path,
            line_start=e.lineno or 0,
            line_end=e.lineno or 0,
            evidence=(e.text or "").strip()[:200],
            description=f"File could not be parsed for AST analysis: {e.msg}",
            impact="Structural analysis skipped for this file.",
            remediation="Fix the syntax error to enable full AST-based analysis.",
        )]

    ctx = _Ctx(file_path=file_path, source_lines=source.splitlines(), findings=findings)
    SecurityASTVisitor(ctx).visit(tree)
    return findings


def analyze_files(file_map: dict[str, str]) -> list[Finding]:
    """file_map: {safe_filename: source_code_text} — only .py files are analyzed."""
    all_findings: list = []
    for name, content in file_map.items():
        if name.endswith(".py"):
            all_findings.extend(analyze_source(name, content))
    return all_findings
