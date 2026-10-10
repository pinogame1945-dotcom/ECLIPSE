# ECLIPSE Phase 2 — ChatGPTへ渡す週間脆弱性情報パッケージ（実装仕様・2026-10-10）

## 役割と開発フェーズ

**ECLIPSEはレポート本文を生成しない。** 公式データを読み取り専用で取得・検証し、「確認された情報・根拠・未確認・取得範囲の限界」をそのままレポート制作者へ引き渡す。掲載する脆弱性の選択・技術的な解説・文章作成・日本語校正は、**別で検証中のChatGPTレポート作成側**の担当。

| フェーズ | 実装対象 | 完了判定 |
|---|---|---|
| 2-A：契約・共通構造 | ZIP構成、出典根拠の境界、公式ソース日付と観測時刻の区別、CVE+ベンダーのreadonly統合 | オフライン契約テスト |
| 2-B：週間データ抽出 | CVE公開日／更新日・KEV登録日で対象候補を漏らさず抽出、関連公式公告を含める、取得不足を明示 | 固定CVE全件DB 403,696・ベンダーV2 160文書で実ZIP生成 |
| 2-C：ChatGPT引渡し保証 | ZIP内すべてのファイルのハッシュ、件数、安全フラグ、固定原本IDを検証。別ランナーから再検査 | JSONL機械読込＋SHA-256再計算・ハンドオフテスト |

**この段階での対象は「固定されたスナップショットから得られる週の候補」であって、常時監視による週の完全網羅とは絶対に称しない。** このゲートを満たして初めて研究用ZIPとして使う。本番の週報データと呼べるためには、継続取込・取得失敗記録・各ソースの観測区間・出版社の公開日や改訂日・翌週との比較が必要。

## 現在のデータと既知の欠落

- CVE: Private Kaggle上の **403,696件、2026-10-10固定原本**。 `date_published` / `date_updated` はCVEレコード内の日時（ECLIPSE初回収集日と異なる）。
- CISA KEV: `kev_current.date_added` と現在の掲載状態（**実際の悪用が確認されたCVE**という公式根拠）。個別の攻撃観測日ではない。
- FIRST EPSS: 予測スコア。現Warehouseの `warehouse_epss` は **score_dateを各行に保持していない**。パッケージ側は `score_date=NOT_PRESENT_IN_WAREHOUSE` と明示し、古いスコアを最新と誤称しない。
- ベンダーV2: **160公告・241版**。メーカー公式URL・観測イベント・SHA-256・解析した `facts_json`。大半が `parsed_unreviewed` であり、メーカー自身の `datePublished` が未保存のソースもある。GitHub Actionsでの初回 `baseline` は **その週の新規公告ではない**。
- Mozilla / Debian: 追加の4文書は別の7日間Artifactだけに存在し、V2には**含まない**。全11情報源の週次網羅を主張しない。
- CVE本文の機械抽出では、技術的原因・攻撃条件・想定攻撃・回避策はNULL/未構造化のまま残す。元CNAの英語説明文に書いてある情報だけをChatGPT側が根拠付きで分析する。

## ZIP v1契約

`ECLIPSE_WEEKLY_EVIDENCE_YYYYMMDD_YYYYMMDD.zip`

```text
manifest.json             固定原本ハッシュ／対象期間UTC／全ファイルハッシュとバイト数／研究用宣言
weekly_index.json         CVE候補総数・関連公告数・選定方式・週次網羅を保証しない宣言
vulnerabilities.jsonl     CVE概要・CNAの影響製品原文／版述語・CVSS・KEV・EPSS・根拠URL
vendor_advisories.jsonl   関連する公式公告の未審査facts・CVE候補・公式URL／ハッシュ／観測イベント
weekly_changes.jsonl      CVE公開・更新・KEV登録・ベンダー観測改訂の区分と日時の意味
evidence.jsonl            出典別URL・原本ハッシュ・正規化の根拠・評価ステータス
quality_report.json       未取得情報源、古いスナップショット、判定不可項目、週網羅不足
```

ISO日付で指定したUTC窓のCVE `date_published` または `date_updated`、KEV `date_added` を起点として**全該当CVE**を抽出。重要度のしきい値で黙って除外しない。CVEがREJECTEDの場合、削除せず `record_state=REJECTED` を保持し **有効な脆弱性として扱わない**。

ベンダー文書は関連する選定CVEの**CVE候補**（誤関連付けの可能性あり）を持つものか、観測した `facts_updated` などの変更イベントが窓内にある文書のみ添付。初回 `baseline` のみなら週次新規公告とはみなさない。データが足りない場合、`quality_report.json` に明示する。

ZIP作成はランナーの読み取り専用SQLite接続で行い、元CVE・ベンダーSQLite、Kaggleプライベートデータセット、mainには書き込まない。再現性のためZIPメンバー名・JSONフィールド順・改行・タイムスタンプを固定する。ファイルを含むマニフェストは相互検証して、検査失敗・ファイルの欠落・規格外の件数があれば全体を失敗とする。ZIPの拡張子だけを信用しない。

## CLI（PRIVATE source DBのみ、顧客データ不要）

```bash
export PYTHONPATH=src
python -m eclipse_l0.weekly_evidence build \
  --cve-db /private/ecl/cve-warehouse.sqlite3 \
  --vendor-db /private/ecl/vendor-v2.sqlite3 \
  --registry config/vendor_source_registry.json \
  --start 2026-10-04 --end 2026-10-10 \
  --require-full-cve \
  --out /private/ecl/ECLIPSE_WEEKLY_EVIDENCE_20261004_20261010.zip

python -m eclipse_l0.weekly_evidence verify \
  --zip /private/ecl/ECLIPSE_WEEKLY_EVIDENCE_20261004_20261010.zip
```

プログラム `src/eclipse_l0/weekly_evidence.py`。回帰テスト `tests/test_weekly_evidence.py`。フルデータ統合用 `.github/workflows/weekly-evidence-handoff.yml`。公式原本を独立復元したランナーで実行してから、生成したZIPを必ず再読み込み検証する。

## ChatGPTへの引き渡し条件

ChatGPTレポート作成側はまず `manifest.json` と `quality_report.json` を読む。**`weekly_coverage_certified=false` または `completeness=UNVERIFIED_WEEK...` なら「今週の全脆弱性を網羅」と書かない。** CVEの初回取り込みで作られたベンダー `baseline` は公開日ではない。KEVの追加日≠攻撃開始日。EPSSの高確率≠実際の悪用の確認。CVEや公式公告の英語本文から推測した攻撃方法は、公式に確認された攻撃観測と別に記す。

**Phase 2-Cのレポート側への実投入は別スレッドで実施**。レポートの品質・不足情報をChatGPT側からフィードバックし、ECLIPSE側で出典の紐付けや不足情報を改善する。本パッケージ自体は最終のレポート形式ではない。

## 次に必須となるもの（Phase 3へのゲート）

- ベンダー新規2社をKaggle V3に安全な世代として収録し、今後の公式情報源を増やす。
- CVE、KEV、EPSS、各ベンダーの**継続収集**を運用し、取得失敗と空振りも観測ログとして記録する。
- ベンダー公式公告の公開日時・改訂日時をソース別に正規化し、`first_seen` / `last_seen` / `publisher_published` / `publisher_updated` / `extractor_changed` を区別する。
- **週間完全性の検査**：カバーした日付・時間、公式一覧のどこまで走査できたか、未解析文書の件数、失敗したソース、各ソースの取得遅延、継続性を必ず検査する。
- 技術的な原因、認証前後の攻撃条件、修正バージョン・回避策など、現DBに構造化されていない情報は、ソース出典の明示と人手検証を伴って追加する。

## 実データ検証結果（2026-10-10）

**Phase 2-A契約・2-B実スナップショットZIP・2-C別ランナー再読込までSUCCESS。**

| 完了ゲート | 確認したこと | 証拠 |
|---|---|---|
| 2-A | JSONL、根拠・週次日付・不足宣言・ZIPハッシュ、同入力からのバイト同一再生成と故意改ざんの拒否 | [オフラインCI SUCCESS](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38057992037) |
| 2-B | PRIVATE Kaggle上のCVE原本**403,696件**とベンダーV2原本**160公告／241版**を独立復元し、**2026-10-04〜2026-10-10 UTC**の研究用週間ZIPを生成。ZIP再読込とSQLite・元ソースハッシュを検証 | [実データZIP作成 SUCCESS](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38057989531) |
| 2-C | **2-Bとは別のまっさらなランナー**がZIP Artifactを再ダウンロードし、**元のCVE原本SHA・ベンダーV2 SHA・マニフェスト・全JSONL件数・品質警告**を検査した。KaggleトークンもソースDBも不要 | [同ワークフローの `independently-read-zip` Job SUCCESS](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38057989531) |

出力Artifact名：`eclipse-weekly-evidence-snapshot-20261004-20261010`（GitHub Actionsの標準保存は**7日間のみ**）。パッケージ自体とbuild-receipt / verify-receiptを収録。現段階で長期保存済みではないので、そのまま週報の商用・恒常供給ができると誤認しないこと。

**品質上の判定は研究用限定である。** 週次の網羅性は `weekly_coverage_certified=false`、新規Mozilla/Debianの4公告は未反映。重要事項・攻撃条件・修正バージョンなどが未確認なら「未確認」のまま渡す。別の週報制作スレッドにおいて読解・執筆実績が出るまで、実運用での週報生成完成とはしない。
