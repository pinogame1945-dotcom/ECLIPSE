# ECLIPSE ベンダーKaggle世代管理：V1 → V2（2026-10-10）

## 実証済み

| 区分 | PRIVATE Kaggle dataset slug | 異なる公告／文書 | 保存版・イベント | Actions証拠 |
|---|---|---:|---:|---|
| 初回 V1 | `eclipse-vendor-evidence-20261010-v1` | 125 | 202 / 202 | [独立復元成功](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38052737015) |
| 増分 V2 | `eclipse-vendor-evidence-20261010-v2` | **160** | **241 / 241** | [新世代作成成功](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38053669895)・[新規ランナーで独立復元成功](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38053761033) |

**実測で異なる公告／文書 +35、履歴版 +39。** 履歴版の増加は「新しいCVE+39件」という意味ではない。原文変化・抽出変更も区別して保持する。

V2保存の作業手順は次のとおり。
1. GitHub Actions の前回アップロード**以前**に保存した信頼済み `vendor-evidence-index.json` を取得する。
2. Kaggle Private V1からDBをダウンロードし、元のSHA-256・SQLite整合性・出典・件数に一致するまで確認する。
3. 元DBは残し、別ファイルに複写して9公式ソースの最新公告・過去公告を制限付きで再取得する。
4. 過去の `vendor_document_versions` を `(source_id, advisory_id, version)` 単位ですべて照合し、履歴の上書き・削除、元の初回観測日時の改変、ベンダーごとの文書件数の減少があれば失敗とする。
5. 新世代用にSHA256・親世代のダイジェスト・ソース別件数・実行証拠を記載したインデックスを作成し、**別のPrivate KaggleデータセットV2を新規作成**する。V1とCVE正本は更新しない。
6. 独立したGitHub ActionsランナーでPrivate V2を再取得し、アップロード前のインデックス、親世代証拠、SQLite整合性と全件件数をチェックした。

実装：`src/eclipse_l0/vendor_kaggle_successor.py`、`.github/workflows/vendor-kaggle-v2.yml`、`.github/workflows/vendor-kaggle-v2-verify.yml`、`tests/test_vendor_kaggle_successor.py`。

## 重要な精度上の課題

ベンダー公式一覧のリンクが、許可された公式HTTPSホスト**以外へリダイレクト**されるケースをAtlassianで確認。安全のため外部への追跡を拒否した。保存できたほかの公告と、未取得の公告・理由を別管理し、**完全網羅成功と誤称しない**。未取得分の確認、発行元の検証、正規化精度のレビューが必要。Kaggleに保存した内容はあくまで `parsed_unreviewed`。

KaggleのV1／V2が存在することは、**将来の世代が自動的に保存され続けることを意味しない**。このV2は1回限りの増分実証であり、スケジュールでの本番自動更新は未承認・未設定。V3以降を連続更新するには、安全な世代ID採番、親世代の競合検出、重複生成防止、旧世代の保持方針、取得エラーの隔離・再試行・監視が必要。顧客データや元ベンダー原本の全面複製も保存対象外。

## CVEとの整合性

最初のV1と本物の**403,696 CVE正本**のID照合は [SUCCESS](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38053519543)：

- MATCHED_PUBLISHED 11,066：文書×CVE候補の**延べ**一致
- MATCHED_REJECTED 13：REJECTEDを独立区別
- UNMATCHED_SNAPSHOT 3：正本に見つからない候補
- UNASSIGNED 23文書：CVE未抽出・未採番
- CVE双方のDBは完全読取専用、固定ソースハッシュで再現可

これはCVE IDの**候補の関連付け**であり、影響製品や修正バージョンの真偽評価ではない。CVE正本の改変、顧客配信は実施していない。

**V2でも本物の403,696件CVE正本との全件ID照合に成功。** [GitHub Actions — V2 READ ONLY x 403,696 CVE SUCCESS](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38053838061)。

| V2の照合分類 | 実測結果 |
|---|---:|
| MATCHED_PUBLISHED | **12,279件（文書×CVEの延べ関係）** |
| MATCHED_REJECTED | **17件（延べ関係）** |
| UNMATCHED_SNAPSHOT | **3件（延べ関係）** |
| UNASSIGNED | **30文書** |

V2の**160文書・241保存版**を別Private Kaggleから独立復元し、固定した403,696件CVE SQLiteと結合した。両正本へ書込み0、CVE原本・KEV・EPSS・保存先を変更していない。11,066→12,279の増加は**CVEユニーク件数の増加ではなく**、新たな公式文書追加に伴う候補リンクの増加。製品・バージョンの実適用性は未審査である。

**本番移行判定：NO-GO。** 保存・復元・独立したID照合の技術実証は成功しているが、全製品・全バージョンの厳密な一致、情報源の網羅性・更新監視・権利確認・運用SLAはまだ検証対象。
