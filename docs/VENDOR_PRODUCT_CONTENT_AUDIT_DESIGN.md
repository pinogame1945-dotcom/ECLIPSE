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

## 【実測監査】固定CVE正本 403,696件 × ベンダーV2 160文書（2026-10-10）

**GitHub Actions：** [本体DB独立復元・全件比較 SUCCESS](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38054491168)、[取得済み証拠だけを別Actionsで要約 SUCCESS](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38054657019)。最新の原本SQLite両方ともKaggle上の検証済みPRIVATEスナップショットから別ランナーで完全復元し、SHA・件数を再確認して**読み取り専用**の比較を実施した。**本物の製品脆弱性の矛盾を3件発見したという意味ではない。**

| 比較状況 | 実測 | 解釈 |
|---|---:|---|
| 構造化された製品claimを走査 | **14,147** | 影響・非影響・fixなどの出版社側の**宣言行**（製品やCVEユニーク件数ではない） |
| 厳密な製品名でCNA行と一致 | **127** | Siemens CSAF 121、Palo Alto JSON 6。**正式に影響が一致したとの意味ではない** |
| Siemens CSAFとCVE CNAの製品名完全一致 | **121** | CSAF statusをCNAバージョン範囲に変換していない |
| Palo Alto生CNA述語が構造的に一致 | **3** | `CVE-2026-0300`の Cloud NGFW / PAN-OS / Prisma Access。共通CNA原文からの複製である可能性あり |
| Palo Alto生CNA述語が構造的に異なる | **3** | **すべて同一 `CVE-2024-0012`** の Cloud NGFW / PAN-OS / Prisma Access。版範囲・更新・JSON表現のレビュー候補、**実際の影響矛盾は未確定** |
| 厳密なCNA製品名一致なし | **13,991** | Red Hat 10,487、Siemens 3,477、Palo Alto 27。別名・対象CNAの不存在・同一製品の版区分など未調査。**「影響なし」「情報に誤り」ではない** |
| CVE原本でPUBLISHEDを確認できない製品claim | **29** | Red Hat 28、Siemens 1。REJECTEDと未登録をここでは合算（別ID照合監査で識別可能） |
| FortinetのHTML本文内CVE↔行紐付け不明 | **28文書** | ページ全体のCVE文字列と影響表を安全に結合できない |
| 対象外HTML/月次CVRF/USN等 | **67文書** | Microsoft月次6、Ubuntu 5、GitLab 28、Atlassian 27、ヤマハ1 |
| Palo Altoの直接CVEスコープなし | **2文書** | PAN-SA独自公告ID等。CVEを捏造して関連付けない |
| 明示された単一バージョンの「影響あり vs 影響なし」対立 | **0検知** | **ゼロが安全性の保証ではない。** 対象外が多く、比較可能な厳密版が少ない |

**重要：14,147の構造化claim中の多くは比較不能だった。** これを一致率やデータの正確性とみなすべきでない。**本番適用の障害はソースからの取得よりも、製品エイリアス・系列・バージョン体系の厳密な関連付け**であることが数値化できた。

### `CVE-2024-0012` の3つの差異について

現在の監査では、Palo AltoメーカーJSONと403,696件の正本に格納されたCNA製品行の生JSONバージョン表現が異なることを検出した。3行は3つの異なるCVEではなく**同一CVE×3製品**。公式メーカー告知にはPAN-OSの修正系列・バックポート等があり、Cloud NGFWとPrisma Accessの扱いはPAN-OSとは別。よって**ただちに“影響バージョンが矛盾する”とは断定しない**。メーカーの公告更新日時・修正経路・CVE正本版を固定して照合し、実際のステータス矛盾と単なるJSON形式差・掲載粒度差を区別する必要がある。

**次の優先事項**：大半を占めたRed Hat / Siemens CSAF製品ツリー名の正規化・商品ファミリー対応を、**人手で検証した限定辞書と根拠パス**に基づいて試験し、CVE CNAに他ベンダー製品情報が存在しない場合は“不可比較”と確定する。次にMSRC CVRFのCVE×ProductTree解析、Ubuntuパッケージ、Fortinet本文スコープを広げる。網羅性・精度を測るまで顧客向け影響あり／なしの自動ラベルは出さない。
