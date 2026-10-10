# ECLIPSE — ベンダー専用Kaggle保存・独立復元・CVE整合性インターフェース（2026-10-10）

**結論：125公告／202履歴版を、CVEデータセットとは完全に分離したPRIVATE Kaggleに保存し、別の新規GitHub ActionsランナーからSHA-256とSQLite検査を通して復元成功。** ただし、CVE本体との全件突合はまだ**未実行**。CVEとの突合エンジンは読み取り専用で実装・単体試験済み。ベンダーの収集データは未審査であり、顧客提供を承認していない。

## 監査証拠

| ステップ | 公式の実行結果 | 検証 |
|---|---|---|
| 収集DBの信頼基準 | [source vendor run 38051672457](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38051672457) | 9情報源の125文書、202版、SQLite OK |
| Kaggle private新規作成 | [seed run 38052640331](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38052640331) | **immutable-create ジョブ SUCCESS**。このワークフロー全体は、独立復元ジョブのTrusted Artifact内のパス間違いでFAIL |
| PRIVATE Kaggleから別ランナーで再取得 | [fresh runner 38052737015](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38052737015) | **SUCCESS**：オリジナルのアップロード前インデックスとバイト単位で一致、全SQLite検査OK |

元SQLite SHA-256：
`cfe17acc36b4be9e449c6dd6c800b709433052da51e1c8a0edb0430cc892d00c`

**Kaggle dataset slug**: `eclipse-vendor-evidence-20261010-v1`（非公開、既存CVE/Kaggleとは独立、作成済みの不変な初期世代）。Kaggleのユーザー名やTokenは公開しない。

作成用は `.github/workflows/vendor-kaggle-seed.yml`、独立読み取り検証は `.github/workflows/vendor-kaggle-verify.yml`。

## 収集データとCVE本体の整合性

ベンダー保存DB（`vendor_documents`、`vendor_document_versions`、`vendor_document_events`）とCVE本体の `cve_current`、`warehouse_metadata` は互いを書き換えない。

`src/eclipse_l0/vendor_cve_link.py` は２つのSQLiteをREAD ONLYで開く。ベンダー版の`facts.cve_ids`を候補として、CVE現在表のCVE IDに照合する。

| 検証結果 | 意味 | 判断 |
|---|---|---|
| MATCHED_PUBLISHED | CVE原本スナップショット内でPUBLISHED | IDが一致するだけ。対象製品への影響は**未確定** |
| MATCHED_REJECTED | CVE原本でREJECTED | 有効な脆弱性と誤認しない |
| MATCHED_OTHER_STATE | CVE原本に存在するが上記以外 | 状態の見直しが必要 |
| UNMATCHED_SNAPSHOT | ベンダーの候補CVEがCVE固定スナップショットにいない | 消さず次のCVE更新で再照合 |
| UNASSIGNED | 公告内の確認できるCVEがない | 公告単位で保存・追跡 |

全CVE照合実行時には `warehouse_metadata.source_index_sha256` と `warehouse_metadata.source_archive_sha256` を結果に残す。これによりどの403,696件CVE正本スナップショットに対して判断したか追跡可能。**未割当と未一致は保存・報告可能な状態であり、エラー扱いで消去しない。** 解析由来のCVEはすべて `EXTRACTED_UNREVIEWED`、HTMLメニューから拾った候補は自動リンクしない。対象製品、脆弱版、修正版の衝突判定は実装前（文字列比較での安易な矛盾認定を避ける）。

試験：`tests/test_vendor_cve_link.py` でPUBLISHED/REJECTED/不在/未採番・READ ONLY・根拠欠落検査を実施。**実際の40万CVEフルDBをダウンロードして行う統合試験は別スレッドの処理と重なるため行っていない。**

実行例（認可されたローカル環境、DBコピーは一時的でCVE側は完全に読み取り専用）:

```bash
PYTHONPATH=src python -m eclipse_l0.vendor_cve_link \
  --vendor-db /private/vendor-restored.sqlite3 \
  --cve-db /private/cve-warehouse.sqlite3 \
  --registry config/vendor_source_registry.json \
  --require-full-cve \
  --out /private/join-receipt.json
```

## 絶対に混ぜないもの

- **CVE原本・統合DB** の既存Kaggleデータセット／main側の更新作業。ベンダーの保存ジョブからは触らない。
- 顧客の資産・利用製品一覧、認証情報、営業秘密。
- ベンダーが提供する原文HTML／JSON丸ごとの再配布。現段階で保存するのは出典付きの正規化済み未審査事実とハッシュ／履歴。
- 速報配信へ未審査の「影響あり・悪用確認」認定を流すこと。

## 未解決のゲート

1. Kaggle初期スナップショットは永続化したが、**新たに取得したベンダー公告を別世代に版管理する処理は未実装**。現時点の監視パイロットは7日間Artifactに依存する。今後はKaggle旧版を独立復元 → 取得差分の監査 → 新世代を作成／前世代を保持 → 別ランナーで照合する処理が必要。新世代の書き込みは並列実行排他と前世代ハッシュの一致確認が必須。
2. ベンダー9情報源の実データについて影響製品とパッチの解析精度を検証すること。
3. CVE本番データとの **403,696件スナップショット固定のREAD ONLY結合結果** を別独立ランナーで実証すること。
4. 商用利用条件・利用許諾と保管範囲の確認。エンドユーザー向けの利用はまだ未承認。
5. 監視対象126候補との対応付け、および実際の情報源全件の網羅性監査。

最優先：**本番CVEの固定スナップショットを変更することなく、次世代ベンダーDBのKaggle独立版管理と実データREAD ONLY結合を検証する。**
