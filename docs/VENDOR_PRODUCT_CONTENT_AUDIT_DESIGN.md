# ECLIPSE — ベンダー公式情報とCVE正本の「製品・バージョン内容」整合性検証

**位置付け：証拠レベルの読み取り専用分析。正式な影響判定、顧客配信、ソース間矛盾の確定ではない。**

## 目的と正本

両データベースはPRIVATE Kaggleの既存スナップショットから個別に独立復元し、SHA-256の原本一致とSQLite整合性を検証する。

- ベンダー：V2、**160文書／241版**。各文書の `source_id`, `advisory_id`, `facts_sha256`, `facts_json` の最新版。
- CVE：原本 **403,696件**。 `cve_current` の状態および `warehouse_affected` のCNA/ADP別の製品・生のバージョン述語を参照。取り込み元は `warehouse_metadata` のソースインデックスハッシュで固定。
- **CVE IDの一致 ≠ 影響製品・バージョンの一致。** 先の12,279リンクも「文書×CVE候補」の延べ件数であり、製品との照合に使えるとは限らない。

## 比較可能な範囲（推測と混同しない）

| ソース種別 | 現在比較する内容 | 明示的に保留する内容 |
|---|---|---|
| Palo Alto Networks（CNA JSON） | CVEが1件と直接識別された文書、製品ベンダー名・製品名の厳密一致。曖昧なバージョン範囲を除外した同一バージョンの影響状態、または構造的に同じ生のCNA述語 | `PAN-SA`独立公告からのCVE自動関連付け、曖昧な製品別名、範囲版の意味判定 |
| Red Hat / Siemens（CSAF JSON） | メーカーがCVEごとに指定した `known_affected` / `known_not_affected` / `fixed` / `first_fixed` 等。CVEのCNA製品表との**完全な製品名**一致を候補として記録 | ProductTreeの複雑な枝・系列・SKUと他社CNA表との別名推論、固定バージョンの算出 |
| Fortinet PSIRT（HTML） | 影響製品と生バージョン・修正文字列自体を原文出典付きで保持 | HTMLページ内に広く出現するCVEはナビゲーション由来の場合がある。**CVE→影響製品**を勝手に結び付けない |
| Microsoft MSRC（月次CVRF） | CVE ID候補の一覧と月次文書の整合 | CVRFの `ProductTree` とCVE毎の `ProductStatuses` が未解析のため、全CVEを全文書の製品に一律適用しない |
| Ubuntu / GitLab / ヤマハ / Atlassian | 保存・出典・CVE候補や公告IDのトレース | Ubuntuパッケージの修正版／HTML本文に出たCVEからの製品影響推論は行わない |

## 判定の意味

- `EXACT_VERSION_STATUS_AGREEMENT_FOR_SHARED_LITERALS`：厳密に同じメーカー名と製品名が特定でき、境界を持たない同一のバージョン文字列で「affected/unaffected」の明示状態が一致。**顧客影響の確認ではない**。
- `EXACT_VERSION_STATUS_DISAGREEMENT_REVIEW_ONLY`：同条件で明示状態が不一致。**出典の別、製品分岐、資料更新差などを人手で確認すべき候補**であり、事実上の矛盾は未確定。
- `PREDICATE_RAW_STRUCTURAL_EQUAL_POSSIBLY_SHARED_CNA`：生のCNAバージョン述語が構造的に同じ。両者が**同じCNA原文を再掲しただけの可能性**が高く、独立した二重確認と称さない。
- `PREDICATE_RAW_STRUCTURAL_DIFFERENCE_REVIEW_ONLY`：構造的に異なるが、版種（semver, rpm, deb）、比較上限、範囲判定方法が違えば同値のこともあるため**検証が必要**。
- `PRODUCT_MATCH_VERSION_SYNTAX_INCOMPARABLE`：製品名は一致するが、影響版の意味を判断できない。
- `PRODUCT_NAME_EXACT_MATCH_CSAF_STATUS_UNMAPPED`：CSAFの製品ツリー名とCNAの製品名が文字どおり合う。ただしCSAFの状態をCNAの版範囲へ自動変換しない。
- `NO_EXACT_CNA_PRODUCT_NAME_MATCH`：厳密な名前が一致しない。**矛盾でも影響なしでもない**。
- `HTML_PAGEWIDE_CVE_LINK_UNVERIFIED`、`DOCUMENT_UNSUPPORTED_FOR_PRODUCT_COMPARISON`：出典関係や製品構造が未実装のため保留。
- `CLAIM_CVE_NOT_PUBLISHED_IN_SNAPSHOT`：CVEスナップショットでPUBLISHED以外（REJECTED、未登録等）。脆弱性が有効とは扱わない。
- 複数のCNA製品行が該当する場合は `MULTIPLE_CNA_PRODUCT_ROWS_NEED_REVIEW`。最初の行を恣意的に選ばない。

すべてに `source_id`, `advisory_id`, CVE ID、vendor facts SHA、CNA製品行番号と値を紐付ける。**解析の母数（構造化claim件数）と保留件数を一緒に記録**し、都合の良い一致結果だけを報告しない。

## 技術的な非破壊保証

- 元SQLiteは双方とも `mode=ro`, `PRAGMA query_only=ON`。Kaggleへの書き戻し・mainの更新・顧客情報の取り込みは不可。
- 最大180,000構造化製品claim／24,000比較候補の上限、各判定の証拠サンプル最大16件。過大・破損データは明示失敗。
- 見かけ上似ている文字列（例：`PAN OS` 対 `PAN-OS`、`7.0.x` 対 `7.0.10`）を安易に統一しない。数値範囲を辞書順・float順で比較しない。
- 監査結果はGitHub Actionsの一時的なJSON証拠だけ。**顧客製品の該当・パッチ緊急度・攻撃悪用を自動確定しない。**

コード：`src/eclipse_l0/vendor_content_audit.py`、テスト：`tests/test_vendor_content_audit.py`。検証ワークフロー：`.github/workflows/vendor-product-content-audit.yml`。実データの実行結果は、最新Actionsが正常終了し具体的件数を確認した後にこの文書へ追記する。

## 次の品質ゲート

(1) CVEごとのMSRC `ProductTree/ProductStatuses` の安全な展開、(2) Ubuntuリリース×パッケージの修正版の構造化、(3) Fortinetの本文に限定したCVEとテーブル行の結び付け検証、(4) 人手で確認した製品別名辞書、(5) 版形式別比較エンジン、(6) 過去公告サンプルによる一致・差異の人手評価と偽陽性／未取得率測定。これらを満たすまで顧客への自動出力にしない。
