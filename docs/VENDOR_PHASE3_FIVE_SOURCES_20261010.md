# ECLIPSE ベンダー拡充 Phase 3 / 最初の5公式情報源

作業対象は `feature/vendor-source-registry-20261010` のみ。**mainを更新しない**。

## 一括候補
- Apple Support: Apple Security Releases。製品単位のセキュリティコンテンツ記事を個別追跡。
- Adobe PSIRT: APSB IDを公表元リストと個別ページで照合。2026年にAdobe Trust Centerへの移転が進んでおりredirect失敗は取得失敗として記録。
- Google Chrome Releases: Google公式ブログのStable/セキュリティ更新記事。本文post-bodyのCVEだけを抽出。
- Google Android Security Bulletins: AOSP月次の個別公告を分けて追跡。
- PostgreSQL Security: PostgreSQL CNAのCVE個別ページを識別子一致で追跡。

これらは公開URLの調査済み**追加候補**であり、公式HTML一覧→詳細の実HTTP/解析/SQLite/Kaggle継続投入は、独立live Actionsが成功し結果を確認するまでは **not_tested**。既存11ソースの実績は維持。26年10月時点の取得環境に依存してページ変更・リダイレクト・認証がありうる。次の信頼ゲートは`.github/workflows/vendor-phase3-five-probe.yml`。

### 実装ポリシー
- 一覧URL→特定公告URL→検証した記事本文だけからCVE IDを抽出し、製品・修正バージョン・悪用状況は推論しない。
- 公表日/更新日が検証できないものはUNVERIFIED、CVE未採番も保存可能な構造。
- 認証・許可のない第三者ホストへはHTTPSリダイレクトを追跡しない。
- 最初の証拠は実行ログ+7日Artifactだけ。Kaggle V1/V2/CVE原本は変更しない。
- 本番昇格は人手による複数公告・版情報確認、ライセンス、継続差分、取得完全性検査後。

統合はmain側の別作業が収束した後、最終ベンダブランチをレビューして一回のPRにまとめる。 


## 実HTTPスモークテスト追記
2026-10-10 Actions #38060777684でApple・Adobe・Android・PostgreSQLの公式一覧→個別公告を1件ずつ取得・解析 PASS。Chromeは公式ブログ個票URLの別ホストへのリダイレクトでFAIL/隔離（**5件中4件のみ検証済み**）。本実行は全体FAILだが個別4件の成功は証拠ログに残る。四件だけ登録簿 `read_parse_verified` に昇格。SQLite一時保存の別実証は専用ワークフローに切り出して未検証のまま扱う。main/V1/V2は無変更。
