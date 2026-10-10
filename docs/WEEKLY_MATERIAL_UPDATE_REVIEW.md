# ECLIPSE 重要な更新情報の検知・審査キュー（2026-10-11）

## 実装目的

従来のL3は **新規KEV6件 + 新規公開CVE44件 = 50件**。CVE dateUpdated のみの行は安全策として L3から除外し、対象週の固定L1スナップショットで **3,685件**が「更新内容未検証」だった。

**dateUpdated が動いた = 危険度が増えた、ではない**。ただし本当に修正対象製品、影響バージョン、緩和策が変更された場合の見落としを放置できない。そのため通常の50件とは別に、**更新内容の差分確認に特化した審査キュー**を追加した。

## 処理方針

1. L1のCVEを全件維持。CVEの更新日だけで重要と判定しない。
2. `vendor_document_versions`（改変禁止・各版に原文ハッシュ）に前後2版がある場合、隣接版を比較。同じパーサー版、ベンダー応答の実バイトが変化、保存済み `facts_updated` イベントが発生、影響製品/版・修正情報・回避策等の **セキュリティ関連フィールドが変わった**時だけ、内容差分の審査候補にする。
3. `CVE V5` の実際の前後原文レコード2版が揃っている場合、`containers.cna.affected`、`metrics`、`solutions`、`workarounds`、`descriptions`、`ADP` などを比較。日付・書式変更は脆弱性内容更新と扱わない。**元のCVE原文2版がないなら解析結果を捏造しない。**
4. 出典が単なるHTML全体のCVE検出では、セキュリティ改訂を別のCVEへ付与しない。原則、厳密に単一CVEへ対応したメーカー情報またはCVE別CSAF構造フィールドだけを紐付ける。
5. `MATERIAL_CHANGE_REVIEW_CANDIDATE`（前後のソース上で関連分野に差異がある）と`UPDATE_REASON_ONLY_BEFORE_STATE_UNAVAILABLE_OR_NO_MATERIAL_PROOF`（履歴不足・判定未了）を厳密に区別し、全行の状態を保全。
6. 検証可能な変更証拠が得られない場合でも、未確認の高CVSS/EPSS候補 **50件までを別キュー**にする。これは調査優先順位であり、週報に自動採用しない。

### 新規実装

- `src/eclipse_l0/weekly_material.py` ：公式ベンダー版管理SQLiteを読み取り専用で検証。2版の出典SHA・抽出器revision・セキュリティ関連差異を監査。
- `src/eclipse_l0/weekly_cve_material.py` ：前後の公式CVE V5原文2版を比較。事前・事後ペイロードSHA照合、CVE ID一致の強制、メタデータ改訂の排除。
- `src/eclipse_l0/weekly_update_queue.py` ：週次L1を保持したまま全対象CVEの更新内容・証拠/未確認理由をZIP化。
- `.github/workflows/weekly-update-content-review.yml` ：固定週原本の監査・独立ランナーでの再計算。履歴の揃ったベンダー実測runを明示指定した場合のみ、オプションでその版管理SQLiteを使う。未指定時は古い内容を復元できないので、証拠0件と明示する。
- オフラインテスト：パーサーバージョン変更、ページ全体のCVE紐付け、表順序だけの変更、メタデータ更新のみ、ハッシュ改ざん、CVE ID誤結合を拒否する。

### 入力と監査上の重要な制約

- 固定週の`source-weekly-evidence.zip`には**CVEの過去の原文バージョンは含まれていない**。現行SQLiteの`cve_current`だけでは過去との内容差を再構成できない。したがって3,685件を`重要でない`とも`重要な変更だった`とも自動判定してはいけない。
- ベンダーSQLiteの `first_observed_utc` / `observed_utc` は**当社の観測日であってベンダーの変更日ではない**。このエンジンは公式改訂日・攻撃実績を保証しない。
- ソース内のCVE/企業影響関係は解釈誤りがありうる。自動公表に使用しない。
- CVE原文2版は将来、正式なアーカイブ取得フロー・出典SHAと組み合わせて入れる。単にJSONとして比較できても**GitHub CVEProjectの真正性を独立検証したことにはならない**。
- 原文を収集していない過去の更新は事後的に検証できない可能性がある。**次週以降の取得フローに、前後版を残す仕組みを統合するまで週次網羅は未達**。

## 再現コマンド

~~~bash
PYTHONPATH=src python -m eclipse_l0.weekly_update_queue build \
  --source-weekly-zip evidence/ECLIPSE_WEEKLY_EVIDENCE_20261004_20261010.zip \
  --out output/ECLIPSE_WEEKLY_UPDATED_CVE_REVIEW_20261004_20261010.zip

PYTHONPATH=src python -m eclipse_l0.weekly_update_queue verify \
  --zip output/ECLIPSE_WEEKLY_UPDATED_CVE_REVIEW_20261004_20261010.zip

# ベンダーSQLiteの履歴が復元できた場合にのみ：
PYTHONPATH=src python -m eclipse_l0.weekly_material build \
  --vendor-db /trusted/vendor-evidence.sqlite3 \
  --registry config/vendor_source_registry.json \
  --start 2026-10-04 --end 2026-10-10 \
  --out output/vendor-material.json

# CVE原文の真正性が別手段で検証された2版ペアがある場合にのみ：
PYTHONPATH=src python -m eclipse_l0.weekly_cve_material build \
  --pairs /trusted/cve-v5-before-after.jsonl \
  --start 2026-10-04 --end 2026-10-10 \
  --out output/cve-material.json
~~~

## 評価設計と今後の統合

新規KEV（掲載確定）／新規公開（危険度選定）／検証済み重要改訂（次フェーズ）を分離して扱う。今回の出力は **重要改訂の検証待ちキュー**で、50件の正式な追加・入替は行わない。

それには (a) 本当に版管理されたソース更新証拠、(b) 必要に応じた人手のソース審査、(c) 製品/CVEの正確な対応、(d) 今週報への適用可能性、(e) 既存の50件との優先順位比較、の一式が必要。日付や未レビューのHTML紐付けだけで自動選抜する実装は避ける。
