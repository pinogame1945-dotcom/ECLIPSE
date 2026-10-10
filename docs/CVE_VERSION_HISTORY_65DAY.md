# CVE V5原文の更新前後履歴 — 2026-10-11 実装仕様

## 何を解決するか

既存の週次固定ZIPでは、CVE原本の`dateUpdated`が変わった3,685件について、以前のCVE原文がないため内容差を確定できなかった。**最新版と更新前版の原文を両方保存**し、`affected`・`metrics`・`solutions`・`workarounds`等の変化を判定可能にする。単なるタイムスタンプ変更は「重大な変更」と認定しない。

既存の`cve_delta.py`が公式CVEProjectの`deltaLog.json`から取得した**新規イベントのCVE IDだけ**を使用し、`https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/...`のCVE V5原文を取得する。フルDBの毎回再取得やGPUは使わない。GitHub Actions無料標準CPUで16〜20本のHTTP同時取得を使う。

## 既存パイプラインへの変更

`.github/workflows/cve-delta.yml`の順序を以下にする（mainに統合するまで定時稼働は開始しない）。

1. `eclipse-state`ブランチの既存チェックポイント・履歴を読み取る。
2. 公式deltaLogをダウンロード。`cve_delta.observe`で対象の時刻グループを全件単位で選ぶ。
3. **追加処理**：`cve_version_history.capture`で該当CVEの最新版原文を同時取得。CVE ID・出典ホスト・サイズ・JSON形式・出典SHAを確認。過去版がある場合は元のバイトと比較し、`weekly_cve_material.compare_pair`でセキュリティ関連フィールド差分を判定する。
4. 原文バイトを圧縮ZIP（`*.cvepack`）に保存。バージョン推移（前後のZIP名・SHA・差分種別・観測時刻）は`events/*.jsonl.gz`に保存。最新バージョンの参照先を`manifest.json`に更新。
5. ローカルで、全保存ZIP/ログのSHAと現行CVE原文IDを再監査する。
6. **全件取得・検証が成功したときだけ**、従来の差分カーソルと新規原文ZIP/台帳を **1回のGitコミット＋push** で更新する。途中の取得失敗ならGitへのコミットは行わず、カーソルも永続化されない。次回は同じ時点からやり直す。

これにより「更新イベントは消費済みなのにCVE原文保存が失敗」という不整合を避ける。

## 最新のCVEしかなかった問題にどう対応するか

**以前に取得していないCVEの初回ダウンロードは必ず `FIRST_OBSERVED_BASELINE_NO_BEFORE`** と表示する。既に`eclipse-state`にdeltaLogカーソルがあっても、CVE原文履歴が存在したと仮定しない。

その後にCVEが更新された場合、前の原文が保存されていれば`CVE_METADATA_ONLY_CHANGE`、`MATERIAL_CNA_SECURITY_CONTENT_CHANGE_REVIEW`、`DESCRIPTION_OR_WEAKNESS_UPDATED_REVIEW`などに分類する。過去版が実在しない3,685件に対して、過去との違いを捏造しない。**元データは既存L1 6,355件、候補50件に影響なし。**

同じCVEが1回のdeltaLog収集間に複数回更新された場合、中間時点の原文は`main`の最新バイトから復元できない。`collapsed_intermediate_events`に件数を記録し、完全な履歴を取得したとは報告しない。

## 保存先・容量・保全ルール

- ストレージ：現行運用のGitHub `eclipse-state`内`data/cve-version-history/`。公開CVEデータのみ。顧客情報は一切入れない。
- 保存形式：`archives/YYYYMMDDTHHMMSSZ-<sha>.cvepack`はCVE原文のバイトを保持。バージョンごとのSHA付き。`events/YYYYMMDDTHHMMSSZ-<sha>.jsonl.gz`は直前バージョンと新バージョンの対応表。`manifest.json`はSHA付き参照インデックス。
- 保存期間：**65日間のローリング履歴**。古いイベントと、活動のないCVEの最終版は期限後に削除される。失われた前後版について比較結果を捏造しない。
- 明示上限：1イベント群最大5,000件／1回の取得5,000CVE／原文1件2MiB／原文ZIPひとつ70MiB／全ローリング保存領域350MiB。上限を超えると**エラー停止**し、イベントだけを先にコミットすることはない。
- Gitの過去コミットに残ったオブジェクトを永久保存・自動削除できるわけではない。**無期限保管は未実装**。長期保存する場合は承認されたKaggle private dataset等に、SHA検証付きで改めてアーカイブする。65日経過後も必ず再取得できるという保証はしない。

## 週次レポートとの接続

`cve_history_export.py`は、保存済みのイベントログを指定週の観測日時で検索して、実際に存在する**更新前後のCVE V5原文ペア**だけを再構成する。これを既存の`weekly_cve_material.py`で重要な内容変更か分類し、`weekly_update_queue.py`に証拠として渡す。

~~~bash
PYTHONPATH=src python -m eclipse_l0.cve_history_export \
  --state-dir /trusted/eclipse-state/data \
  --start 2026-10-11 --end 2026-10-17 \
  --pairs-out /private/cve-before-after.jsonl \
  --summary-out /private/cve-history-export-summary.json

PYTHONPATH=src python -m eclipse_l0.weekly_cve_material build \
  --pairs /private/cve-before-after.jsonl \
  --start 2026-10-11 --end 2026-10-17 \
  --out /private/cve-content-material-review.json
~~~

- `source_fetch_utc`はdeltaLogの観測インデックス時刻、`observed_utc`はECLIPSEが元原文を取得した時刻。**ベンダー側の変更日時ではない**。
- GitHub `main`上の可変原文をTLSで取得しSHAを付けるが、**取得対象の上流GitコミットSHAを固定していない**。中間リビジョンの完全網羅や発行元の真正性を独立して証明したとはみなさない。
- 同じCVEが週内に複数回更新された場合は週初期/週末期の原文ペアで比較し、中間変化の存在を警告する。途中で追加→削除された変更を見落とす可能性があるため、イベントログを必ず残す。
- `candidate_for_material_security_review`は**審査対象**であって、攻撃の存在・顧客影響・パッチ確定を意味しない。
- 重要50件は新規KEV＋新規公開CVEsで別途確保。重要更新を正式に混合する優先順位付け・人手レビューは次段階で行う。

## テストと非破壊検証

`tests/test_cve_version_history.py`は、初回baseline、改訂後の対象版変更、メタデータのみ、同一周期の重複イベント、欠落・改ざんの拒否、deltaLogカーソルの退行/再実行拒否、観測履歴からの週次版ペア再構成を検証する。

`.github/workflows/cve-version-history-pilot.yml`は**featureブランチ限定・書込権限なし**で、CVEProject公式原文を実際に1件取得→圧縮保存→別途SHA付きで再読込できるか確認する。既存`eclipse-state`・`main`は一切書き換えない。**実環境の4時間ごとの定期保存は、本変更をmainへ統合した後**に初めて開始される。
