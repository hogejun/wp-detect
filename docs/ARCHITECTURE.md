# アーキテクチャ（core）

`wp-detect` は、サイトが WordPress かを判定しバージョンを抽出し、セキュリティ上重要なレスポンスヘッダを受動検査する、小さな読み取り専用スキャナです。チェックはプラグインとして拡張できます。

## パッケージ構成
```
src/wp_detect/
  __init__.py   パッケージ版・console-script エントリポイント(wp-detect)
  cli.py        引数解析・実行フロー・終了コード
  http.py       HTTP クライアント（オリジン制限・リダイレクト制御・予算・URL検証）
  scanner.py    チェックの選択(--only/--skip, requires 推移解決)と実行
  models.py     Finding / CheckResult / Component / Severity / ScanResult
  report.py     端末表示と JSON 化
  testing.py    テスト用モックサーバ（serve / wordpress_app）＝公開 API
  checks/
    base.py     Check 基底・registry・ordered_checks・validate_registry（拡張点）
    detect.py   WordPress 判定・バージョン検出（order=0）
    headers.py  セキュリティヘッダ/Cookie フラグの受動検査
```

## HTTP クライアントの安全設計（`http.py`）
- **同一オリジン内に留まる**: リダイレクトは自前解決し、初期ターゲットと同一オリジン（scheme/host/port）内のみ追跡。逸脱は拒否（SSRF/スコープ逸脱防止）。
- **低負荷**: リクエスト予算と間隔。リダイレクトのホップも予算・スロットル対象、ホップ上限・ループ検出あり。
- **環境プロキシ不使用**: `trust_env=False`。
- **URL 検証（`normalize_target`）**: scheme 省略時 `https://` 補完（bare `host:port` は host+port）。userinfo・クエリ・フラグメント（空の `?`/`#` 含む）・制御/空白/バックスラッシュ・不正ポート・`//` 始まり・非 HTTP(S) scheme を拒否。`normalize_target`/`safe_display` は共通内部関数で scheme 判定。
- **秘密値の非露出**: 境界違反・不正 URL 由来の例外は固定理由のみ（生 URL を埋めない）。ログ/表示は `safe_display`（`scheme://host[:port]`、不正入力は `<target>`）。

## チェックの拡張点（`checks/base.py`）
- `Check` 契約: `id`/`name`/`description`/`requires_wordpress`/`order`（実行順, detect=0）/`requires`（依存チェック id）＋`add_arguments(parser)`/`configure(args)`（CLI フック, 既定 no-op）＋`run(client, scan) -> CheckResult`。
- 発見: 組み込み(detect/headers)は直接 import、他は `wp_detect.checks` entry point group から load（名前順・失敗は entry point 名付きで致命＝fail-loud）。
- `validate_registry()` が `requires` 未登録・順序違反（依存がより小さい `order` で登録されているか）を起動時に検証。
- `scanner.select_checks` は `--only` 指定時に `requires` を推移的に引き込む。

## スキャンの流れ
`cli.main` が URL を検証して `http.Client` を構築 → `scanner.scan` が `detect` を先頭に各チェックを実行 → `requires_wordpress` が真のチェックは非 WordPress サイトでスキップ（理由を記録）→ `detect` 自体が到達不能なら例外を伝播し CLI はエラー終了。`CheckResult.status`（ok/skipped/partial/failed）を `ScanResult.scan_status`（complete/partial/failed）に集約。

## テスト
`wp_detect.testing` のモックサーバと `httpx.MockTransport` で外部 I/O なしにコア・detect/headers・URL/リダイレクト/予算・秘密非露出を検証。CI は `uv run pytest` と `actionlint`。
