# 週報候補を「新規」「重要な更新」の二本立てに分離

2026-10-11の確定方針：更新CVEは、新規KEV＋新規公開を中心とした50件の**外側で別集計**する。更新が増えたから新規50件が減ることはない。

## 週報の論理構造

| 週報カテゴリ | 集計対象 | 取り扱い |
|---|---|---|
| A. 新規の重要脆弱性（目標約50） | 新規CISA KEV（必須）＋対象週新規公開CVE（重要126候補＋危険度） | `new_kev_and_disclosures.jsonl`。新規50枠は維持。 |
| B. 既存脆弱性の重要な更新（件数無制限） | 既存CVEの影響版、修正情報、緩和策、CVSSなどに、観測された**原文差分のあるCVE** | `material_update_research_only.jsonl`。更新内容を確認するまで顧客向け重要更新と断定しない。 |
| B' 更新内容の未確認・調査優先 | 更新日が動いたものの履歴が不足して内容変更未確認のCVE | `unverified_update_high_risk_watch.jsonl`は最大50件のサンプル。**週報本文の重要更新件数には含めない**。 |

AとBは**CVE単位で二重計上しない**。新規公開と新KEVが同週に重なればAの新規KEV枠を優先。今週新規公開されたCVEがその後同週に修正された場合もAにまとめる。Bは新規イベントがない既存公開CVEの改訂だけを対象にする。

Bの更新候補に50件という上限は設けない（0件も認める）。更新が大量発生した場合でも、判断に使う詳細調査のコスト・レポート表示は別途制御する。**データの保存上限と報告上限を混同しない**。

## 対象固定週の既知数値（2026-10-04〜10）

- L1全文脆弱性候補：6,355件（出典ZIPを両方にバイト同一で封入）
- **A**: 50件＝新規KEV6件＋新規公開44件（重要126候補との一致を含む）
- **B**: 既存CVEで更新日時のみが週内のものが3,685件。この時点で、保存済みの前バージョンによってセキュリティ内容変更を判断できたものは0件。
- **B'**: 3,685件が**更新内容未確認または未照合**。うち危険度優先の調査サンプル50件。更新がなかった、無害だ、という結論ではない。

過去の3,685件について更新前CVEの原文が存在しないため、既存のCVE V5原文履歴システムを使って今後の週に備える。後から欠落した前版を作らない。

## 実装と受け渡し

- `src/eclipse_l0/weekly_section_handoff.py`：既存の`weekly_important`と`weekly_update_queue`がそれぞれ検証したZIPをそのまま封入。
- `weekly_distinct_section_summary.json`：A・B・B'を別集計した機械可読な数値と、未確認事項。
- `new_kev_and_disclosures.jsonl`：新規枠50件（出典元の影響製品等も含む）。
- `material_update_research_only.jsonl`：内容差分のある更新の審査候補（未検証の修正内容を確定とはしない）。
- `unverified_update_high_risk_watch.jsonl`：未確認更新の調査サンプルだけ。全3,685件は内包する`existing_cve_update_evidence.zip`の`updated_cve_decision_ledger.jsonl`に保存。
- `new_cve_candidate_evidence.zip`／`existing_cve_update_evidence.zip`：それぞれの検証済みZIPを原バイトで保持。両ZIP中のL1は**バイト完全一致**しない場合停止。
- `weekly_section_manifest.json`：全ファイルのSHA-256。独立ランナーで読み込み、両ZIPを原本から再計算し、A/Bの重複CVEと集計不整合を拒否する。

パケットは週報本文や顧客影響判断の自動生成ではなく、**他のChatGPTによるレポート製作に渡す検証可能な資料**である。フォント・レイアウトのテンプレート変更もしない。

## 運用上の留保

新規CVEの週内公開情報と、ECLIPSEがその更新を観測した時刻は異なる。保存のない期間は網羅性を保証しない。Bは公式情報・変更内容・攻撃条件・自社の利用製品・影響バージョン等を確認して初めて、週報掲載可能な「重要更新」になる。

なお、`CVEの変更原文ペア`を処理するモジュールは既にあるが、メインの定時取込が未統合である間は履歴が継続蓄積されない。新しい更新が全て判定できたという主張はしない。

## 操作

~~~bash
PYTHONPATH=src python -m eclipse_l0.weekly_section_handoff build \
  --new NEW_KEV_AND_CVE_RESEARCH_20261004_20261010.zip \
  --updates EXISTING_CVE_UPDATE_REVIEW_20261004_20261010.zip \
  --out WEEKLY_SEPARATED_NEW_AND_UPDATES_20261004_20261010.zip

PYTHONPATH=src python -m eclipse_l0.weekly_section_handoff verify \
  --zip WEEKLY_SEPARATED_NEW_AND_UPDATES_20261004_20261010.zip
~~~

実データへの構築と別ランナーでの完全再計算は`.github/workflows/weekly-separated-new-and-updates.yml`で行う。mainは変更しない。
