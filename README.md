# wp-detect

サイトが **WordPress かどうかとそのバージョン**を判定し、**セキュリティ上重要なレスポンスヘッダ/Cookie フラグ**を受動的に検査する、軽量な検出ツールです。

- **無害・読み取り専用。** 送信するのは通常の GET のみ。認証試行・書き込み・エクスプロイト・サービス妨害は一切行いません。
- **低負荷。** リクエスト間ディレイと総リクエスト数の上限。リダイレクトは対象オリジン内に限って自前で追跡（スコープ外への逸脱を拒否）。
- **拡張可能。** チェックはプラグインとして追加できます（下記）。

> ⚠️ 自分が所有するサイト、または明示的に許可を得たサイトに対してのみ使用してください。

## 必要環境
- [uv](https://docs.astral.sh/uv/) / Python 3.13+

## 使い方
```bash
uv sync
uv run wp-detect https://example.com
uv run wp-detect --json https://example.com      # JSON 出力
uv run wp-detect --list-checks                    # チェック一覧
```

> 対象 URL: scheme 省略時は `https://` を補完（`localhost:8080` は host+port 扱い）。クエリ/フラグメント/認証情報(userinfo) は不可（空の `?`/`#` のみでも拒否）。エラー文に入力 URL は出しません。

### 主なオプション
| オプション | 説明 | 既定 |
| --- | --- | --- |
| `--json` | JSON 出力 | 無効 |
| `--list-checks` | チェック一覧を表示して終了 | - |
| `--only` / `--skip` | 実行/除外するチェック id（カンマ区切り。detect は常に実行） | - |
| `--delay` / `--timeout` / `--max-requests` | 礼儀・上限 | 0.3 / 10 / 200 |
| `--insecure` | TLS 検証を無効化 | 無効 |
| `--user-agent` | UA 上書き（エイリアス可: chrome/firefox/…/wp-detect） | Chrome |

## 同梱チェック
| id | 内容 |
| --- | --- |
| `detect` | WordPress 判定とコアバージョン開示検出（generator・`/readme.html`・RSS・REST ルートなど公開リソースのみ） |
| `headers` | セキュリティヘッダ欠如・`X-Pingback`・Cookie フラグ（Secure/HttpOnly）の受動検査（WordPress 判定時のみ実行） |

## 出力と重大度
各チェックは観測を **Finding** として返します（High/Medium/Low/Info）。終了コードは Medium 以上があれば `1`、なければ `0`、接続不能は `1`、引数エラーは `2`。`--json` には `detail`/`remediation`/`scan_status` も含まれます。

## プラグイン（チェックの追加）
チェックは `wp_detect.checks.base.Check` のサブクラスです。別のディストリビューションから追加するには、そのモジュールを `wp_detect.checks` エントリポイントグループに公開します（import 時に `@register` が走ります）。

```toml
# あなたのプラグインの pyproject.toml
[project.entry-points."wp_detect.checks"]
my_check = "my_pkg.my_check"
```

```python
from wp_detect.checks.base import Check, register
from wp_detect.models import CheckResult, Finding, Severity

@register
class MyCheck(Check):
    id = "my_check"
    name = "My check"
    description = "..."
    order = 100                 # 実行順（detect=0 が最初）
    requires = ()               # 出力に依存する他チェックの id

    def run(self, client, scan) -> CheckResult:
        r = CheckResult(self.id)
        # client: wp_detect.http.Client（benign GET/HEAD のみ）
        return r
```

テストには `wp_detect.testing`（`serve` / `wordpress_app`）でモック WP を立てられます。公開 API は `checks.base.Check`＋`register`／`wp_detect.models`／`wp_detect.http.Client`／`wp_detect.testing`（0.x の間は変更あり得ます）。

## 開発
```bash
uv run pytest
uv build
```

## ライセンス
[MIT](LICENSE)
