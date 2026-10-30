"""Inspect response headers of the homepage for hardening signals.

Entirely passive: a single GET of the homepage yields everything this check
needs. We report three things:

  * **Missing security headers** — CSP, X-Frame-Options, etc. Their absence is
    not a vulnerability per se, but their presence materially reduces the blast
    radius of several web attacks (clickjacking, MIME sniffing, protocol
    downgrade).
  * **X-Pingback** — advertises the XML-RPC endpoint; a passive corroboration
    of the dedicated xmlrpc check.
  * **Cookie flags** — Set-Cookie lines lacking Secure/HttpOnly.
"""

from __future__ import annotations

from ..models import CheckResult, Finding, Severity
from .base import Check, register

# header name -> short reason it matters.
_SECURITY_HEADERS = {
    "content-security-policy": "XSS/データ注入の影響を緩和",
    "x-frame-options": "クリックジャッキング対策",
    "x-content-type-options": "MIME スニッフィング対策 (nosniff)",
    "strict-transport-security": "HTTPS 強制 (HSTS)",
    "referrer-policy": "リファラ経由の情報漏えい抑制",
}


def _cookie_flag_issues(set_cookies: list[str]) -> list[str]:
    """Return human-readable issues for cookies missing Secure/HttpOnly."""
    issues: list[str] = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        missing = [
            flag
            for flag, token in (("Secure", "secure"), ("HttpOnly", "httponly"))
            if token not in low
        ]
        if missing:
            issues.append(f"{name or '?'} ({', '.join(missing)} 無し)")
    return issues


@register
class HeadersCheck(Check):
    id = "headers"
    name = "Response headers"
    description = "Report missing security headers, X-Pingback and weak cookie flags."

    def run(self, client, scan) -> CheckResult:  # type: ignore[no-untyped-def]
        result = CheckResult(self.id)
        home = client.get("/")

        # -- A1: missing security headers -----------------------------
        missing = [h for h in _SECURITY_HEADERS if h not in home.headers]
        if missing:
            detail = "; ".join(f"{h}: {_SECURITY_HEADERS[h]}" for h in missing)
            result.findings.append(
                Finding(
                    check=self.id,
                    id="headers:missing-headers",
                    title=f"セキュリティヘッダが {len(missing)} 件欠如",
                    severity=Severity.LOW,
                    detail=f"未設定のヘッダ: {detail}",
                    evidence="missing: " + ", ".join(missing),
                    remediation="Web サーバ/テーマで該当ヘッダを付与する。",
                )
            )

        # -- A2: X-Pingback -------------------------------------------
        pingback = home.header("x-pingback")
        if pingback:
            result.findings.append(
                Finding(
                    check=self.id,
                    id="headers:x-pingback",
                    title="X-Pingback ヘッダを検出",
                    severity=Severity.INFO,
                    detail="XML-RPC エンドポイントが広告されています（xmlrpc 有効の受動的シグナル）。",
                    evidence=f"X-Pingback: {pingback}",
                    remediation="XML-RPC が不要なら無効化し、このヘッダも抑止する。",
                )
            )

        # -- A3: cookie flags -----------------------------------------
        issues = _cookie_flag_issues(home.set_cookies)
        if issues:
            result.findings.append(
                Finding(
                    check=self.id,
                    id="headers:cookie-flags",
                    title="Cookie に Secure/HttpOnly が不足",
                    severity=Severity.LOW,
                    detail="フラグ不足の Cookie はセッション盗聴や XSS 経由の窃取に弱くなります。",
                    evidence="; ".join(issues[:10]),
                    remediation="セッション系 Cookie に Secure と HttpOnly を付与する。",
                )
            )

        if not result.findings:
            result.findings.append(
                Finding(
                    check=self.id,
                    id="headers:clean",
                    title="ヘッダ/Cookie に目立つ問題なし",
                    severity=Severity.INFO,
                    detail="主要なセキュリティヘッダが揃い、Cookie フラグも問題ありませんでした。",
                )
            )
        return result
