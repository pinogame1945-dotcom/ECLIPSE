# ECLIPSE Phase 2-D — 全CVE保持・重要候補整理・詳細分析素材の3層受け渡し

**役割**：ChatGPTによる週間脆弱性レポート制作に、**全件のCVE情報を捨てず**、読む順番と確認すべき根拠を分けて渡す。ECLIPSEはレポートの執筆・掲載決定・顧客影響確定をしない。

## 3層の関係

| 層 | 内容 | 何を保証するか |
|---|---|---|
| **L1：全件** | 上流の週間情報ZIPを**バイト列・SHA-256が完全に同一**の `source-weekly-evidence.zip` として無改変で同梱する | ベンダーでCV​​Eを事前に絞らない、REJECTEDも状態付きで記録する、最終判断を後からやり直せる |
| **L2：注目候補** | `priority_candidates.jsonl`、公開CVEの客観的なルール順と選定根拠を記録 | ベンダーを問わずKEVや重大CVEを拾う。ルール対象外はL1に残す。掲載決定とは無関係 |
| **L3：分析用詳細候補** | `deep_dive_candidates.jsonl`、CNAのオリジナル説明・影響述語・CVE原本SHAと、関連メーカー公告の引用先・ソースSHA・未確認情報を対応付ける | 詳細なレポートを書くための根拠の入口。**メーカーの影響・修正版の一致や実攻撃を確定しない** |

原本に対してCVEの独立した絞り込みをかけないのが最大の方針。重点監視11情報源に限らず、CVE全体を扱う。

## L2の透明な候補抽出ルール

順位は *ルールに基づく注意順* であり、脆弱性の危険度の数学モデルではない。

| 順位 | 事実として確認する条件 | 解釈上の注意 |
|---|---|---|
| P0 | その週に **CISA KEVへ登録** され、CVE原本がPUBLISHED | 実際の悪用が認められたCVE。ただし攻撃開始時刻・顧客攻撃の確認ではない |
| P1 | KEVに掲載されているPUBLISHED CVE | 今週新たに悪用されたとの意味ではない |
| P2 | CVEのCNAが示すCVSS基本値が **9.0以上** | CVSS評価元と評価日時に依存する。深刻度は影響確定ではない |
| P3 | FIRST EPSSが**0.5以上** | 現DBにscore_dateがないため**固定時点の予測値**として扱い、最新値と主張しない |
| P4 | CNAが示すCVSS基本値が**7.0以上** | その他の高スコアCVE |
| P5 | 公式ベンダー公告内でCVEの**候補リンク**を確認 | HTMLなどは未審査のCVE↔製品関係を含み得る |
| WATCHLIST | 上記なし | L1に保持し、週報側が再調査・選定可能 |
| INACTIVE | REJECTEDなど非PUBLISHEDの原本状態 | 「有効な脆弱性」として扱わず、参照はL1から可能 |

**どの層でも、REJECTEDを「重大な有効脆弱性」に上げない。** P5のベンダー候補も公的確認ではなく `UNREVIEWED` と明示する。重要順位の数値スコアによる不透明な足切り・選抜は実装しない。

L3対象は **P0～P3の全候補** および **P4でメーカー公告の参照が付く候補**。公式メーカー文書が存在しなくてもKEVや重要CVSSの候補は落とさず、`NO_OFFICIAL_VENDOR_ADVISORY_IN_FIXED_SNAPSHOT` を付けて調査必要として渡す。P5単独などの候補はL2とL1からアクセスできる。

## ZIP形式と検証

`ECLIPSE_WEEKLY_EVIDENCE_3LAYERS_YYYYMMDD_YYYYMMDD.zip`

```text
triage_manifest.json          親ZIPのSHA256、ファイルごとのSHA256、サイズ、未検証事項
triage_index.json             ルール／階層別の件数／L1が全件である保証
priority_candidates.jsonl     L2: 重要候補・順位付け根拠／CVE-ID／関連公告キー
deep_dive_candidates.jsonl    L3: CNAの根拠原本とベンダー資料への出典参照・不足項目
triage_quality.json           現時点の監視範囲、欠測、EPSS日時不明、誤結合注意
source-weekly-evidence.zip    L1: 週間CVE全件＋40関連公式公告＋根拠の本来のZIPを無改変収録
```

**二重の検証**：ベース原本ZIPは元のmanifest/件数/全ファイルSHAを検査し、3層ZIPの各ファイルも新しいmanifestにハッシュを保存する。さらに**保存済みL1を再解析してL2とL3をゼロから再計算して完全一致を要求**する。攻撃者または誤処理がL2の重大CVEを抜き、L2側のハッシュを書き直しても、L1と突合してエラーにする。オフラインで同じ入力を使えばZIPの全バイトが一致する。

Python CLI：
```bash
export PYTHONPATH=src

python -m eclipse_l0.weekly_triage build \
  --source-weekly-zip /private/ECLIPSE_WEEKLY_EVIDENCE_20261004_20261010.zip \
  --out /private/ECLIPSE_WEEKLY_EVIDENCE_3LAYERS_20261004_20261010.zip

python -m eclipse_l0.weekly_triage verify \
  --zip /private/ECLIPSE_WEEKLY_EVIDENCE_3LAYERS_20261004_20261010.zip
```

コード：`src/eclipse_l0/weekly_triage.py`、安全性テスト：`tests/test_weekly_evidence.py`、実データワークフロー：`.github/workflows/weekly-evidence-triage.yml`。元の403,696件CVE正本と160文書ベンダー正本、Kaggle、mainは**一切変更しない**。

## レポート制作側とのインターフェース

別スレッドのChatGPTは、まず `triage_index.json` と `triage_quality.json` に目を通し、L2で重要候補を把握した後、L3の根拠素材を確認する。L3に必要な記載がない場合は、L1の `source-weekly-evidence.zip` を開いて元の `vulnerabilities.jsonl` / `vendor_advisories.jsonl` / `evidence.jsonl` を確認できる。

最終掲載はChatGPT側の判断。L2・L3に上がらなかったCVEを掲載することも認める。候補のランキングが一致していても、継続収集の不足やベンダー側の公告の日付が未構造化であれば、**「今週の情報を完全に網羅した」と言ってはならない**。

**次の品質課題**：CVE/KEV/EPSS、ベンダー公告の継続更新、公告自身の公開日と更新日、ベンダーV3の独立Kaggle保存、抜けているメーカーの網羅率測定、L3での攻撃条件・技術的原因・修正版の厳密な根拠抽出。これらは情報収集基盤のPhase 3で扱い、レポート本文生成では代替しない。
