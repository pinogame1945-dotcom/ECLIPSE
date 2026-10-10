# ECLIPSE — 重要候補約50件への選抜（実装契約・2026-10-10）

## 目的と位置付け

週報作成AIに渡す**優先確認候補**を約50件に絞る。**本文作成・実際の掲載決定はしない**。
元のL1（週のCVE全候補）は無変更でZIPに丸ごと内包し、監査用decision_ledger.jsonlには全CVEと選定・非選定理由を残す。L1の取りこぼしや偽の「週次網羅完了」宣言は拒否する。

## 選定順位（3本柱）

1. **新規CISA KEV追加：全件確定**。週間の`CISA_KEV_DATE_ADDED_IN_WINDOW`があり、公式CISA KEV presentで、CVEがPUBLISHEDのみ。古い既存KEVはこの無条件枠に紛れ込ませない。
2. **承認済み126候補のベンダー：全件確定**。CVE CNA原本の`affected.vendor`が承認済み126行のベンダー名・明示aliasに一致する場合のみ確定。曖昧な部分一致やベンダーのHTMLに偶然登場したCVEへのリンクでは確定しない。CNA名が不完全なら取りこぼしの可能性を品質フラグで提示。
3. **その他：危険度シグナルに応じて残り枠**。過去のKEV掲載 +70、EPSS（保存時刻不明）0.5以上 +60／0.1以上 +35／0.01以上 +10、CNA CVSS 9以上 +25／7以上 +12。55点以上のみ残り枠を使う。CVSSだけでは入らない。点数は**優先順位の仮の運用規則**であり、検証済みリスク、実攻撃、顧客影響の判断ではない。

**50は目標値、強制上限ではない**。①＋②だけで50を超えた場合、該当CVEは1件も落とさず、`mandatory_overflow`に超過数を出す。対策製品・ベンダー公告ごとの統合は後工程で扱い、CVEの消失・誤結合を隠す目的には使わない。

## 126行の指定ファイルについて — 未完了のゲート

前スレッドで確定した`ECLIPSE_標準監視ソース調査_126候補_20261010.xlsx`の**126行の実データは現GitHubリポジトリ内で未取得**。
既存`config/vendor_source_registry.json`は**13の公式ソース候補/検証レコード**しか収録されていないため、**126ベンダーと偽って自動補完・代用しない**。

Excelの承認済み行を次のJSONに正確に変換して、`config/important_vendor_126.json`として別途配置する必要がある。

~~~json
{
  "schema_version": 1,
  "expected_unique_vendors": 104,
  "entries": [
    {"vendor": "承認済みの実際のベンダー名", "aliases": ["CNAが用いる表記揺れ"]}
  ]
}
~~~

`entries`は実際に126行であることが必須。同一ベンダーがカテゴリ違いで複数行ある場合は繰り返し登録可。別ベンダーに同じaliasを付けると衝突として**異常終了**する。記載されている`expected_unique_vendors`は、Excelと実データの重複集計に合致する値だけを指定する（前スレッド調査では104候補）。上の例は**仕様例であって126行の実装データではない**。

また、126候補の名簿と、公式ソース126件の接続・永続収集成功は別である。名簿登録で監視網羅性は保証しない。現時点の13公式ソースのベンダー監視カバレッジも`False`とする。

## 使い方

~~~bash
export PYTHONPATH=src
python -m eclipse_l0.weekly_important build \
 --source-weekly-zip /private/ECLIPSE_WEEKLY_EVIDENCE_20261004_20261010.zip \
 --vendor-policy config/important_vendor_126.json \
 --target 50 --min-score 55 \
 --out /private/ECLIPSE_IMPORTANT_50_20261004_20261010.zip
python -m eclipse_l0.weekly_important verify \
 --zip /private/ECLIPSE_IMPORTANT_50_20261004_20261010.zip
~~~

**ZIPメンバー**：
- `source-weekly-evidence.zip`: 既存L1の全件・全根拠ZIP。元ファイルとバイト単位で同一。
- `important_vendor_126.json`: 実行に使用した承認済み名簿の元バイト。
- `important_candidates.jsonl`: 優先確認候補（KEV→126ベンダー→他リスクの順）。
- `decision_ledger.jsonl`: L1の全件に対する非掲載候補も含む決定証跡。
- `important_index.json`: 件数・重複を除いた枠内内訳・超過・名簿SHA256。
- `important_quality.json`: 未審査データ、最新EPSS日付欠落、週次完全性・ベンダー収集範囲未証明。
- `important_manifest.json`: L1、選抜・名簿・各ファイルのSHA256、再検証パラメータ。

作成後の`verify`は元のL1 ZIPのmanifestとハッシュ・件数を照合し、**L1＋126ベンダー名簿から選抜を独立再計算して全バイト一致**を要求する。非選抜CVEの削除やパラメータ変更を検出する。

## 現状・本番投入条件

- 完了：新ロジック／自己検証器／安全性オフラインテスト、既存のL1/L2/L3と非破壊で並行可能。
- 未完了：承認済みExcel実データのJSON変換、実データ6,355件での50件近傍への収束検証・しきい値調整、126ベンダーすべての収集検証。
- 原本固定スナップショットの限界：新規KEVとCVE日付は**CISA登録日・CNA原本の日付条件**。実攻撃開始時刻や現在の監視網羅性ではない。
- 公開repoに非公開顧客資産・API鍵・私人情報を置かない。独立ランナー・GitHub無料標準CPU・既存データのread-only運用を維持する。
