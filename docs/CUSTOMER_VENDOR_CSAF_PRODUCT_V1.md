# ECLIPSE — 顧客利用製品に紐付くRed Hat / Siemens公式CSAF情報 V1

**目的**：ベンダー公式公告とCVE番号の全体一致を調べるのではなく、「顧客が利用する製品名」を入口として**その製品に紐付いた公式脆弱性情報**を根拠付きで抽出する。現行V1は**顧客端末への実際の影響あり／なしを断定しない調査候補**である。

## 二つの開発との関係

1. 既に`main`に存在する `src/eclipse_reports/customer_products.py` は、顧客の製品リストを**ローカル・非公開環境**で受け取り、固定CVE 403,696件／KEV／EPSSからJSON・CSV・編集可能PPTXを生成する。メーカー名＋製品名の**完全一致**で候補を出し、導入バージョンは表示のみ。
2. このPRの `src/eclipse_l0/vendor_product_monitor.py` は、PRIVATE Kaggleで独立復元検証済みの**ベンダーV2 160文書／241履歴版**から、**Red HatおよびSiemensのCSAF製品ツリーID・製品名・CVE別ステータス・対象製品ID明示の対策記述**を厳密に取り出す。顧客製品と実製品IDを関連付ける機能はこの第二層が担う。
3. 2つの出力を**個別の根拠として併記**するのが次の正式レポート設計。顧客側の利用製品IDと出典ハッシュで照合し、影響／修正版を自動的に上書きしない。ベンダーDBとCVE正本も相互に更新しない。

現時点では**V1の公式ベンダー照合機能は完成しているが、両者を統合した顧客向けPPTXの本番出力と人手承認ワークフローは未実装**。

## 入力のプライバシー

顧客の製品情報、社名、設置バージョンなどは**公開GitHub、GitHub Actions、公開・非公開のKaggle**にアップロードしない。社内許可済みのPC／隔離環境内で、別々に復元したCVEとベンダーのSQLite、顧客製品JSONを使ってローカル実行する。

旧 `customer_products.py` と共通の必須JSON部分を使うが、CSAF専用のオプション `csaf_product_id` を追加できる：

```json
{
  "schema_version": 1,
  "customer_name": "PRIVATE_LOCAL_ONLY",
  "products": [
    {
      "id": "local-server-type-a",
      "vendor": "Red Hat",
      "product": "<公式CSAFに掲載された正確な製品名>",
      "csaf_product_id": "<任意：公式CSAFの正確な製品ID>",
      "installed_version": "<表示のみ・影響未判定>"
    },
    {
      "id": "local-controller-type-b",
      "vendor": "Siemens",
      "product": "<公式CSAFに掲載された正確な製品名>",
      "installed_version": null
    }
  ]
}
```

製品名、製品IDは**最初に公式CSAF製品カタログから選択**する。あいまいな部分文字列・製品別名の自動適用は禁止。たとえ製品名が一致しても、CSAF内に複数の製品IDがある場合は `MULTIPLE_PRODUCT_IDS_REQUIRE_SELECTION` として止める。別メーカーに同名の製品があっても結び付けない。

## 実行手順（PRIVATEローカル／顧客名・バージョンの流出防止）

検証済みのPRIVATE KaggleベンダーV2を許可済みローカルマシンに復元した後：

```bash
export PYTHONPATH=src
python -m eclipse_l0.vendor_product_monitor catalog \
  --vendor-db /private/ecl/vendor-v2.sqlite3 \
  --registry config/vendor_source_registry.json \
  --source redhat-csaf \
  --out /private/ecl/redhat-official-product-catalog.json

python -m eclipse_l0.vendor_product_monitor catalog \
  --vendor-db /private/ecl/vendor-v2.sqlite3 \
  --registry config/vendor_source_registry.json \
  --source siemens-csaf \
  --out /private/ecl/siemens-official-product-catalog.json

python -m eclipse_l0.vendor_product_monitor assess \
  --vendor-db /private/ecl/vendor-v2.sqlite3 \
  --registry config/vendor_source_registry.json \
  --inventory /private/customer-products.json \
  --out /private/vendor-product-evidence-review.json
```

カタログには製品ID・公式製品名・ベンダー情報の何行に登場するかを表示する。**出現数は脆弱性の発生数ではなく、また全製品の網羅性証明ではない**。顧客の機器名とメーカーの正式製品名が異なる場合は、ユーザー承認済みの正確なメーカー製品IDを個別に選択する。

出力JSONは、顧客側の製品ID、CSAF掲載製品ID、公式製品名、公告ID、CVE、メーカーの製品状態（`known_affected`, `known_not_affected`, `fixed`, `first_fixed`, `under_investigation`）、ソースURL、CSAFの証拠JSONパス、原文のSHA-256、解釈されたfactのSHA-256を返す。**対策テキストはCVE IDと製品IDを明示している場合だけ**紐付ける。グループのみ／製品指定なしの対策を根拠なく付け加えない。

例：`first_fixed` と書かれたメーカーの製品ステータスはそのまま表示するが、顧客のインストール版が修正済みであること、導入すべきパッチ番号、サービスへの露出を証明したと扱わない。

## 安全な判定

| 結果 | 意味 |
|---|---|
| `EXACT_PUBLISHER_PRODUCT_ID` | 顧客が明示したメーカー製品IDと名前の両方が一致 |
| `EXACT_PUBLISHER_NAME_ONE_ID` | 公告中に製品名が一致し、製品IDが一意に特定された |
| `MULTIPLE_PRODUCT_IDS_REQUIRE_SELECTION` | 同名に複数メーカー製品ID。人手選択まで判定しない |
| `NO_CVE_ASSIGNED` | メーカー宣言に直接紐付くCVE IDがない |
| `NO_EXACT_PUBLISHER_PRODUCT_LABEL_IN_SNAPSHOT_NOT_PROOF_OF_SAFETY` | 現スナップショットに厳密一致する証拠なし。**安全との証明ではない** |

どの結果でも `customer_version_impact=NOT_ASSESSED`、`fixed_version_certified=false`、`notification_approved=false` を強制。

顧客別候補レポートにCVE・KEV・EPSSを追加する場合、`main`側の正本スナップショットを**別途読み取り専用で参照**し、CVEのREJECTEDやソース取得時刻を反映させる。KEV掲載／EPSS高値を、顧客侵害の確認と同一視しない。

## 検証範囲と残課題

- 全自動回帰テストは `tests/test_vendor_product_monitor.py`。曖昧なID、他社誤一致、CSAF内の別CVEのパッチ誤帰属、製品未検出、巨大製品名、顧客への導入版影響の過剰断定、SQLite非破壊などを検証。
- リアルデータ実証は `.github/workflows/vendor-csaf-private-demo.yml`。**公式公開製品カタログから選んだ製品名で、架空の製品リストをランナー内だけで生成する**。実顧客の入力・製品一覧・ベンダー告知の全文をPublic Artifactに載せず、集計結果だけをアップロードする。
- **顧客向け本番リリースはNO-GO**：配布許諾、CVEごとの最新性、導入版の厳密比較、Red Hatパッケージ／RHELリリース差、SiemensハードウェアSKU・ファームウェアの対応、製品IDの未収録や別名の検証、正式承認・配信操作を別途確認する。

次は両方のPRIVATEデータをローカルで結合する**顧客向けレポート出力アダプター（レビュー待ちの証拠を付録として明示）**を作る。未審査のベンダー情報で顧客報告本文の影響判定を上書きしない。
