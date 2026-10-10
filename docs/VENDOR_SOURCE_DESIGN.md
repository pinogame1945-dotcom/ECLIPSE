# ECLIPSE 公式ベンダー情報源・正式設計候補 v1（2026-10-10）

**状態：設計候補／本番採用前レビュー待ち。** JPCERT/CCの掲載頻度は監視対象の採用条件にしない。市場選定による14カテゴリ・126候補から、**ベンダーごとではなく情報源ごと**に接続性を検証する。製品群数 ≠ API／フィード数。未検証は未検証のまま保持し、推測で「対応済み」にしない。

## 確認済みと未確認（根拠付き）

正本は `config/vendor_source_registry.json`。この文書中の「PASS」は**代表サンプルについて一覧→詳細にアクセスし読めた**という限定的な意味。長期監視・全件網羅・商用再配布が可能という保証は **一切ない**。各レコードにはソースID、製品スコープ、取得形式、正規URLと許可ホスト、最終確認時刻、Actions実行URL、確認事実、残作業、使用許諾状態を保存。

| 公式情報源 | 状態 | 実証した範囲 | 公式ソースへの課題 |
|---|---|---|---|
| Fortinet PSIRT | 取得・解析実証 | RSS 50件、詳細HTML 4件、影響／修正表 | CVE分解、真の更新差分、履歴保存 |
| Microsoft MSRC | 取得・解析実証 | 一覧193件、月次CVRF XML（約32MB） | 製品ツリー変換、メモリ制約、大きな月次差分 |
| Palo Alto Networks | 取得・解析実証 | Critical絞り込み一覧9件、CVE個票JSON | 全重大度・ページング・影響版整合 |
| Red Hat | 取得・解析実証 | CSAF releases.csv、個票JSON | 旧CVE一覧APIは失敗、CSAFから補完／増分取込 |
| Siemens ProductCERT | 取得・解析実証 | CSAF索引841件、個票（3 CVE） | バージョン判定・TLP／権利 |
| ヤマハネットワーク | 取得・解析実証 | 案内ページとUTX200/UTX100の詳細HTML | 別レイアウト、ファームウェア適用性 |
| GitLab | 取得・解析実証 | patch-release Atom 107件、個別記事でCVE記述 | 通常パッチとの区別、修正版構造化 |
| Canonical Ubuntu | 取得・解析実証 | USN一覧5件、USN個票JSON | リリース・パッケージごとの状態 |
| Atlassian | 取得・HTML解析実証 | セキュリティ一覧、Confluenceの個票 | **ページ全体からのCVE抽出はナビゲーションを誤読する**。記事本文の限定が必須 |
| Google Chrome | **失敗／未採用** | 旧Atom URLが非HTTPSのFeedBurnerへ誘導 | HTTPSで検証可能な公式セキュリティ更新源の再発見 |
| Cisco | **未実証** | OAuth認証付きopenVuln API候補 | 正規認証と条件確認後に限定的PoC |

> 保護原則：GitHubのpublicブランチには**実顧客名、利用製品一覧、認証情報、未公開脆弱性**を格納しない。無償標準GitHub Actionsだけで検証し、有償runner・保存は使わない。

## 正式アーキテクチャ（設計）

```text
CORE: 市場選定した主要製品       WATCH: KEV/CVE/NVD等       CUSTOM: 顧客製品（非公開）
         │                               │                           │
         ▼                               ▼                           │
  ソース登録簿（公式URL、取得方式、条件、状態）                [非公開照合のみ]
         │                               │                           │
         ▼                               ▼                           │
  形式別取得（API / RSS / JSON / CSAF / HTML / OAuth）          │
         │                               │                           │
         ▼                               ▼                           │
  イミュータブル版管理：source + advisory ID + source hash      │
         │                               │                           │
         └───────────────┬───────────────┘                           │
                         ▼                                           │
           CVE／公告ID／影響製品の関連付け（推測リンク禁止）       │
                         │                                           │
           原文根拠のある正規化・矛盾保持／欠落表示                 │
                         │                                           │
                         ▼                                           ▼
           重要度・速報／日報／週報／顧客向け出力（公開と非公開分離）
```

情報源は**CVEより先に通知する可能性がある**ので、アドバイザリ固有IDを主キーとしてCVEsは複数・ゼロ件を許容する。逆に1 CVEが複数ベンダー／公告にある場合は事実を上書きせず、証拠参照を残す。KEV未登録は「悪用なし」ではない。EPSSは予測値であり「悪用確認」と混同しない。

## 実装に追加した保存用境界

`src/eclipse_l0/vendor_store.py` は、すでに `read_parse_verified` になった情報源の**正規化された公告詳細と根拠情報**を、ローカルSQLiteに版管理して保存する最小の台帳。まだ公式ベンダーとの自動接続はない。

| テーブル | 用途 |
|---|---|
| vendor_documents | `(source_id, advisory_id)` ごとの現行ハッシュ・初回／最終観測 |
| vendor_document_versions | 各版の正規化済みJSON、ベンダー原文SHA256、原文URL、抽出の承認状態 |
| vendor_document_events | 初回baseline、情報更新、本文変更のみの区別 |

**初回取り込みを新着アラートにしない。** 同じ内容なら版を増やさない。原文SHAのみ変わり正規化事実が変わらなければ `source_changed_only` とし、脆弱性更新と混同しない。一次資料のURLとSHAだけでは後日の原文再現性は保証できない。原文本体の保存は利用条件を確認して許可された**別の非公開耐久ストレージ**で行う（現段階では未実装）。

### 正規化する最小フィールド

`source_id`、`advisory_id`、`source_url`、`source_sha256`、`observed_utc`、`extract_status`、`facts: {title, cve_ids[], affected[], evidence_fields[]}` を必須とする。個別の `affected` は文言や出典の正確性が確認できるまで製品影響「確定」とはしない。将来は `product_status`、`remediation`、`exploit_status`、`publication_history` 等を追加できるが、原文の各フィールドを必ず参照する。

## 本番昇格のゲート（全てが必要）

| Gate | 必須の証明 |
|---|---|
| 1 正規ソース | HTTPS・許可ホスト・配信形式・認証・権利条件確認 |
| 2 発見 | 公式情報の新規／改定、一覧から詳細までの一貫した取得 |
| 3 内容 | CVE/公告、影響製品・正確なバージョン、修正・非該当、出典照合 |
| 4 差分 | 初回baseline、再走冪等、本文の改定、削除誤判定回避 |
| 5 保管 | 耐久DB、移行、バックアップ、復旧試験（publicには顧客データなし） |
| 6 健全性 | 成功HTTP ≠ 成功パース、遅延、無更新、データ破損、失敗通知 |
| 7 品質 | 過去の公式公告を母集団とする取りこぼし評価、誤抽出率の評価 |
| 8 顧客提供 | 利用規約・商用再利用、法的審査、公開情報と顧客秘匿情報の分離 |

### CI・運用コマンド

```bash
PYTHONPATH=src python -m eclipse_l0.vendor_registry --registry config/vendor_source_registry.json
PYTHONPATH=src python -m unittest discover -s tests -v
```

PoCの実行結果は原則GitHub Actionsの短命なArtifactだが、**失効後も実績が失われないよう**正本JSONに証拠実行URLと検証事実を継続保存する。重要な判断に使った内容は必要に応じハッシュと許可された証拠を別アーカイブへ保管する。新規ベンダーの追加は「候補→実データ収集→登録簿で検証済み→本番ゲート」の順番。検証失敗のベンダーも削除せず原因と次の手順を残す。

**未実装のものを「できた」と書かない。これは接続性と解析能力の設計検証であり、正式な連続監視のSLA達成報告ではない。**

## 実収集→詳細保存の統合PoC（2026-10-10）

**9ソースの公式一覧→詳細→正規化→ローカルSQLite保存→同一データ再取込をGitHub Actionsで実行し、9/9成功。** これは`read_parse_verified`からの発展だが、本番可否を保証するものではない。

- 実行ログ・証拠：[GitHub Actions 38048877850](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38048877850)
- 動作コード：`src/eclipse_l0/vendor_pilot.py`
- 実行方式：`.github/workflows/vendor-evidence-pilot.yml`（同名の検証ブランチ push と明示的手動実行のみ。定期監視ではない）
- 選択対象：Fortinet、Microsoft、Palo Alto Networks、Red Hat、Siemens、ヤマハ、GitLab、Ubuntu、Atlassian。
- 実測：9情報源から**代表アドバイザリ各1件**、合計9件を保存。DB `quick_check=ok`。9 baselineイベント、9不変の再取込を確認（イベントの重複は0件）。
- Microsoftについては2026-Oct CVRFの240 CVE IDを抽出。ただし**240件の個別製品影響を確認した意味ではない**。
- FortinetはFG-IR-26-175の影響/対策表4行、Palo AltoはCVE-2026-0300の影響表3行、SiemensはSSA-627195の9製品IDをそれぞれ未審査として保存。Red Hat CSAF、Ubuntu USNも個別公告を保存。
- GitLab、ヤマハ、Atlassianは**HTMLのページ全体に含まれるCVEを確定した関連脆弱性とはみなさない**。見出し／URL由来とページ全体由来の候補を分ける。構造化された正確な影響バージョンの抽出は未完了。
- レジストリは `one_shot_evidence_pipeline` に成功実績、Action URL、1件、baseline 1件、replay 1件、保管条件を記録。将来のPRでも検証実績が散逸しない。

**運用上の強い制限：** DBはGitHub Actionsの実行環境で作られ、Artifact保持は7日。毎回実行時に前回の保存DBを自動復元することはしていない。元のベンダー本文は蓄積せず、SHA256と出典URL・出典フィールド、未審査の正規化情報だけを保管。したがって「継続的にデータが蓄積されている」「詳細がすべて正しく抽出されている」とは**言えない**。顧客向け自動配信、本番用持続ストレージ、情報源の網羅率、商用再配布権利、定期更新監視はいずれも未実装。

### 再現用のコマンド

```bash
PYTHONPATH=src python -m eclipse_l0.vendor_registry
PYTHONPATH=src python -m eclipse_l0.vendor_pilot \
  --registry config/vendor_source_registry.json \
  --db output/vendor-evidence.sqlite3 \
  --out output/vendor-evidence-manifest.json \
  --max-items 1
PYTHONPATH=src python -m unittest discover -s tests -p 'test_vendor*.py' -v
```

次の合格ゲートは、(1) 許諾を確認した**非公開の永続保存先**を準備すること、(2) 異なる実行間でDBを復元して**本当の更新差分**を観測すること、(3) パーサー項目をソース横断で監査すること、(4) 承認済みのCORE/WATCH/CUSTOMへのリンクを構築すること、(5) ベンダーごとの権利と更新間隔を確定させること。

## 異なるGitHub Actions実行間でのDB復元・再検証（2026-10-10）

**別実行での復元・差分記録を実データで検証済み**。CVE全件基盤・Kaggle保存処理には手を加えていない。

| 実行 | 証拠 | 保存内容 |
|---|---|---|
| 第1回（初回） | [one-shot pilot](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38048877850) | 9件・9版・9イベント |
| 第2回（過去Artifactから復元） | [cross-run pilot #1](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38049736195) | 9件・11版・11イベント（Fortinet/AtlassianのHTML原文ハッシュ変更のみ2件） |
| 第3回（第2回のArtifactを復元） | [cross-run pilot #2](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38049818582) | 9件・13版・13イベント（原文ハッシュ変更のみ2件） |

**確認した事実**：過去の成功した実行からSQLiteファイルを取得→SHA・コンテンツハッシュ・外部キー・DB整合性と出典ホストを確認→ローカル復元→9件を再取得→同一事実なら上書き・baselineの再発行はしない→結果を次回用Artifactに書き出す。異なる実行での継承を2回連続で確認した。情報源別の最新実証結果は `config/vendor_source_registry.json` に記録。

- 生のHTML変更だけで重要な脆弱性更新とはみなさない。`source_changed_only` は構造化事実の変更 `facts_updated` から区別する。今回実際のセキュリティ事実更新は **0件**であり、その真の運用検証は次の課題。
- SQLite改ざん・欠落、履歴のハッシュ不一致、前回の成功実行があるのにArtifactが存在しない状況は**自動初期化せず失敗**とする。
- 同じ前回版からの再実行・復元に伴う重複アラートは生まない。単体テストでは仮の影響バージョン変更が版更新になることを別々のDBの間で確認した。
- GitHubの7日間Artifact以外の永久保存先はまだない。7日以上実行しなかった場合は原則復元不可になる。**継続的・長期の永続保存と呼べる状態ではない**。
- 本収集はスケジュール未有効・顧客配布未有効・原文再配布未承認、詳細抽出は `parsed_unreviewed`。保存は9ベンダーの代表各1件のみ。ソース群の網羅性証明にはならない。

実装：`src/eclipse_l0/vendor_replay.py`、`src/eclipse_l0/vendor_pilot.py`、`tests/test_vendor_replay.py`、`.github/workflows/vendor-evidence-pilot.yml`。複数ベンダーの1件だけを積み増す小規模PoCなので、次段階の本番化には非公開永続ストレージ、製品/バージョン別の解析精度評価、掲載変更の異常検知、法的な利用条件確認が必要。
