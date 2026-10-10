# ECLIPSE 監視対象ベンダー拡大・第1弾（2026-10-10）

## 実施結果

ユーザー方針：顧客向けレポート生成を一旦後回しとし、公式ソース収集対象のベンダー拡大を優先する。

今回、既存9情報源に**Mozilla／Debian**を追加。**11情報源の公式エンドポイントが「実際に到達・取得・正規化・SQLite初回保存・重複しない再実行」まで実証済み**となった。

| 新規ソース | 主な製品・種別 | 独立した実証で取得した2件 | CVE IDの扱い | 影響・修正版 |
|---|---|---|---|---|
| Mozilla MFSA | Firefox, Firefox ESR, Thunderbird | `MFSA-2026-104`, `MFSA-2026-103` | 公式MFSAのHTML main/article部分のCVE参照のみ | 公告タイトル中の「修正済み」は記録するがCVE×製品×バージョンの詳細は未認定 |
| Debian DSA | Debian全般とパッケージ | `DSA-6550-1`, `DSA-6549-1` | Debian公式announcementの `CVE ID:` ヘッダーに限定。未記載・解析できなかったCVEは不明のまま保存 | Debianリリース／パッケージ別のバージョン比較は未実装 |

## GitHub Actions で成功を確認した内容

| 観点 | 成功した実行 | 結果 |
|---|---|---|
| 2ベンダー×2件、公式サイトの一覧と詳細をHTTPS取得、SHA-256を算出、CVEの誤関連付けを防止 | [**公式URLからの実取得・正規化 PASS**](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38056308256) | **2/2情報源、4/4詳細** |
| 初回SQLite保存・replayによる重複書込回避・SQL整合性 | [**SQLite 4件・履歴4版・再実行4件すべて不変 PASS**](https://github.com/pinogame1945-dotcom/ECLIPSE/actions/runs/38056416467) | **4件・4版・4イベント、quick_check=ok** |

独立SQLiteのSHA-256: `fc4943e59add60d979ad7ea9e0c790ff91d8a9922be73c463f0bdb054466ca3c`。

現状の正式登録簿：`config/vendor_source_registry.json`。各ソースのステータス `read_parse_verified` は**公式の読み取り／解析の小規模実証済み**のみを意味し、全公告・全製品・全バージョンのカバーを保証しない。保存したメーカー公告の原文全体や実顧客情報は公開リポジトリに追加していない。

## 新規実装

- `src/eclipse_l0/vendor_additional_sources.py`：Mozilla MFSA／Debian DSAの特定公告のみを抽出する独立アダプター。ソースの公式ドメインホワイトリスト、公告ID一致、CVE候補の出典範囲固定と誤関連付けを実装。
- `src/eclipse_l0/vendor_pilot.py`：新規アダプターを既存9ベンダーと同じ実行系につなぐ。各ソース独立に `--sources` を指定可能。
- `tests/test_vendor_additional_sources.py`：広告・ナビゲーション欄に現れた誤CVE、公告ID不一致、メーカー公式URL条件などをテスト。
- `.github/workflows/vendor-new-sources-probe.yml` / `.github/workflows/vendor-new-sources-sqlite.yml`：外部課金ランナーなしの少量検証、既存Kaggle保存を変更しない。

## 未実装・本番上の重大な限界

**新しく取得した4文書は7日間GitHub Actions Artifactの検証保存であり、既存PRIVATE Kaggle V1=125文書／V2=160文書にはまだ統合していない。** 現時点で「PRIVATE Kaggleに164件保存済み」「全11社の毎日自動監視開始」とは主張できない。旧世代を変更しない安全なKaggle次世代作成（V3）と独立復元が必要。収集網羅性、CVE対応の検証、商用利用・権利確認、製品版情報の根拠監査も残る。

## 次の拡大方針

1. **既存候補の復旧**：Google Chrome（HTTP転送するフィードを避けた公式HTML配信で取得再試験）、Cisco（OAuth非依存の公式公告一覧の権利・取得方法を確認）。
2. **企業での採用度が高い未対応ベンダー**：Apple、VMware/Broadcom、Oracle、SAP、Adobe、Juniper、HPE、Dell、IBM等。独立した公式告知・エンドポイント・認証制約と配布条件を調べ、2〜5ソースずつ小規模実証する。
3. **126候補の照合**：ユーザーの既存126候補一覧と、実際の公式URL、重複する法人／製品、固定版の抽出精度、日付更新の有無、営業利用規約をマッピングする。未検証の名前を登録するだけで「対応済み」とはしない。
4. **ECLIPSEベンダーPRIVATE Kaggle世代V3**：検証済み前世代のSHAと単調増加履歴、失敗ソースの隔離を守り、既存V1・V2を不変としたまま追加ソースを保存・再検証する。

優先順位は**公式取得の成功件数・対象製品の重要度・修正バージョンの明確さ・継続運用可能性**とする。顧客向け影響判定は別の承認ゲートが通るまで開始しない。
