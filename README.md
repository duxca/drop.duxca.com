# drop

短いテキスト（ワンタイムログイン URL、一時的な API キーなど）を **1 回だけ** 受け渡す、使い捨ての伝言板（dead drop）。
Muse のブラウザ側エージェント（フォーム POST しかできない）と Muse VM の間の受け渡しに使う。

- 公開 URL: `https://drop.duxca.com/<token>`（専用サブドメインのルート直下）
- 状態はプロセスのメモリ内だけ。DB もファイルも使わない。**再起動 = 全消去** が正しい性質。
- 書き込みは 1 回、読み出しも 1 回（読んだ瞬間に消える）。TTL は既定 10 分。

## 位置づけ

**一時受け渡し専用。** 長期のマスター鍵、長寿命のパスワード、ルート権限の鍵のようなものは流さない。
流してよいのは「漏れても短時間で失効する／受け取ったらすぐ差し替えられる」ものだけ（ワンタイムログイン URL、
発行直後にローテーションする API キーなど）。

## 流れ

```
VM 側                         drop                         ブラウザ側
  | POST /admin/drops (admin)   |                              |
  |---------------------------->|                              |
  |<-- {token, url_path} -------|                              |
  |  (https://drop.duxca.com/<token> をブラウザ側に伝える)       |
  |                             |<--- GET /<token> (フォーム) --|
  |                             |<--- POST /<token> text=... --|
  | GET /<token>?take=1         |                              |
  |---------------------------->|  (値を返してその場で削除)      |
  |<-- 200 text/plain ----------|                              |
```

逆向き（VM 側からブラウザ側へ渡す）ときは、admin 発行時に `text` を先入れし、
受け手に `https://drop.duxca.com/<token>?take=1` を開かせる（1 回だけ表示され、その場で消える）。

## エンドポイント

### 公開側（`DROP_PUBLIC_ADDR`、nginx から中継する）

トークン自体が capability。アカウント・パスワードはない。

| リクエスト | 状態 | 応答 |
|---|---|---|
| `GET /<token>` | 未投稿 | 200 フォーム（`textarea name="text"`） |
| | 投稿済み | 200「受付済み」だけ（値は出さない） |
| | 存在しない／期限切れ／回収済み | 404 |
| `POST /<token>`（`application/x-www-form-urlencoded`、`text` 1 つ） | 未投稿 | 200「受付済み」 |
| | 投稿済み | 410 Gone |
| | 1024 字超 | 413（保存しない） |
| | 空文字 | 400（保存しない） |
| | 存在しない／期限切れ／回収済み | 404 |
| `GET /<token>?take=1` | 投稿済み | 200 `text/plain; charset=utf-8` で値。その場で削除 |
| | 未投稿 | 409 Conflict（「まだ」。ドロップは残る） |
| | 存在しない／期限切れ／回収済み | 404（「消えた」） |
| 上記以外のパス・メソッド（`HEAD`、`/`、`/admin/...` 等） | | 404 |

- 字数は Unicode スカラ値の数（バイト数ではない）。フォームの `maxlength` は表示用で、本命はサーバ側の強制。
- リクエストボディ自体の上限は 16 KiB（1024 字が全部 4 バイト文字でパーセントエンコードされても収まる大きさ）。超過は 413。
- `take` の値は `1` だけ。`take=0` や `take` の重複は 404。`take` 以外のクエリは無視する。
- ブラウザの textarea は改行を CRLF にして送る。値は送られたまま保存・返却する（trim しない）。

### admin 側（`DROP_ADMIN_ADDR`、nginx から中継しない）

公開側とは別の loopback ポート。公開ポート側に admin ルートは存在しない
（nginx 中継後の送信元も loopback になるので、送信元 IP では公開と admin を区別できないため）。

| リクエスト | 応答 |
|---|---|
| `POST /admin/drops`（`Content-Type: application/json`） | 201 `{"token": "...", "url_path": "/...", "ttl_secs": 600}` |
| `DELETE /admin/drops/<token>` | 204（消した）／404（存在しない・期限切れ） |

`POST /admin/drops` のボディ（どちらも任意。未知のフィールドは 400 系で拒否）:

- `text`: 先入れする値。入れると投稿済み状態で作られる（公開側 POST は 410、take で 1 回だけ回収できる）。1024 字超は 413、空文字は 400。
- `ttl_secs`: 1 〜 `DROP_MAX_TTL_SECS`。省略時は `DROP_DEFAULT_TTL_SECS`（既定 600）。範囲外は 400。

上限に達しているときは 503。`Host` ヘッダが loopback 名（`127.0.0.1` / `localhost` / `[::1]` 等）でないリクエストは 403（DNS rebinding 対策）。

## 脅威モデル

### 守れるもの

- **トークンを知らない第三者による読み書き。** トークンは OS の CSPRNG による 128bit（base64url 22 字）。推測は現実的に不可能。安全の本体はコードの秘密ではなくこの推測不能さ（Yopass と同じ考え方）。
- **値の二重読み出し。** take は 1 回で削除する。誰かに先に取られた場合、正規の受け手は 404 になるので **気付ける**（防げはしない。下記）。
- **上書き。** 書き込みは 1 回だけ（2 回目は 410）。先入れしたドロップも公開側からは上書きできない。
- **公開経路からの admin 操作。** admin は別ポート・別ルータで、公開ルータには admin ルートが無い。nginx も admin ポートへ中継しない。両ポートとも loopback 以外での待ち受けは起動時に拒否する。
- **投稿内容による XSS。** 値は `text/plain` でしか返さず、フォームページにも出さない。全応答に `Content-Security-Policy: default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`、`X-Content-Type-Options: nosniff`、`Cache-Control: no-store`、`Referrer-Policy: no-referrer` を付ける。HTML は静的文字列で JS なし。
- **長期残留。** TTL（既定 10 分、上限は設定）で消え、プロセスが止まれば全部消える。ディスクには書かない（サンプルの systemd unit は swap・コアダンプも止める）。
- **ログへの混入。** サービスは本文・トークン・設定値をログに出さない（リクエストログも取らない）。サンプルの nginx 設定はボディを記録せず、ディスクの一時ファイルにも書かせない。
- **メモリ枯渇。** ドロップ数・本文の合計バイト数・ボディサイズ・TTL に上限がある。

### 守れないもの

- **URL（トークン）が漏れた場合。** チャット履歴、ブラウザ履歴、エージェントのログ、nginx のアクセスログ（パスは残る前提）などで URL を見た人は、正規の相手より先に投稿・回収できる。先取りは 404／410 で検知できるだけ。
- **`?take=1` 付き URL の扱い。** リンクプレビューやクローラが take URL を GET すると、その時点で値は消費される。take URL はチャット等に貼らない（貼るのはフォームの URL だけ）。フォームの URL は GET しても値を消費しない。
- **送り手の真正性。** トークンを持っていれば誰でも書き込める。受け手は「正しい相手が書いた」ことをこのサービスからは確認できない。
- **端末側・ホスト側の侵害。** 送り手／受け手のエージェントやブラウザ、TLS を終端する nginx、ホストの root はすべて値を見られる。メモリ上の値は解放時にゼロ化していない（HTTP スタックのバッファにもコピーが残りうる）。
- **可用性。** 再起動で全部消える。上限到達時は 503。レート制限は持たない（必要なら nginx 側で）。

## 使い方（curl）

```sh
ADMIN=http://127.0.0.1:8471     # admin ポート（同じホストから）
PUBLIC=http://127.0.0.1:8470    # 本番では https://drop.duxca.com

# 1. 発行（空）
curl -sS -X POST -H 'Content-Type: application/json' -d '{}' "$ADMIN/admin/drops"
# => {"token":"<22 字>","ttl_secs":600,"url_path":"/<22 字>"}
TOKEN=<上の token>

# 2. ブラウザ側は https://drop.duxca.com/$TOKEN を開いてフォームから送信する。curl で代わりにやるなら:
curl -sS --data-urlencode 'text=<渡したい値>' "$PUBLIC/$TOKEN"

# 3. 回収（1 回だけ。2 回目は 404）
curl -sS "$PUBLIC/$TOKEN?take=1"

# 投稿待ち（409 の間はまだ。404 は消えた／期限切れ）
while :; do
  code=$(curl -sS -o value.txt -w '%{http_code}' "$PUBLIC/$TOKEN?take=1")
  case $code in 200) break ;; 409) sleep 2 ;; *) echo "gone ($code)" >&2; break ;; esac
done

# 値を先入れして発行（TTL 5 分）。値をシェル履歴やコマンドラインに出さないようファイル→標準入力で渡す
# （jq -Rs はファイル末尾の改行も値に含める）
jq -Rs '{text: ., ttl_secs: 300}' < value-file \
  | curl -sS -X POST -H 'Content-Type: application/json' --data-binary @- "$ADMIN/admin/drops"

# 明示破棄（204 / 404）
curl -sS -o /dev/null -w '%{http_code}\n' -X DELETE "$ADMIN/admin/drops/$TOKEN"
```

## 設定

環境変数で設定する。カレントディレクトリの `.env` も読む（`.env.example` 参照）。設定値はログに出さない。

| 変数 | 既定 | 意味 |
|---|---|---|
| `DROP_PUBLIC_ADDR` | `127.0.0.1:8470` | 公開側の待ち受け。loopback 必須 |
| `DROP_ADMIN_ADDR` | `127.0.0.1:8471` | admin 側の待ち受け。loopback 必須、公開側と別 |
| `DROP_DEFAULT_TTL_SECS` | `600` | 発行時の既定 TTL（秒） |
| `DROP_MAX_TTL_SECS` | `3600` | `ttl_secs` の上限（秒） |
| `DROP_MAX_DROPS` | `1000` | 同時に存在できるドロップ数（未投稿を含む） |
| `DROP_MAX_TOTAL_BYTES` | `1048576` | 預かり中の本文の合計（UTF-8 バイト）。4096 以上 |
| `RUST_LOG` | `info` | tracing のフィルタ |

固定値: 本文 1024 字、リクエストボディ 16 KiB、期限切れの定期パージ 30 秒ごと（アクセス時にも遅延削除する）。

上限の考え方: 本文は合計 1 MiB、ドロップ数 1000 で、エントリのオーバーヘッドを含めても数 MiB に収まる。
一時受け渡しで同時に数十件を超えることは想定しない。上限に達すると、期限切れを掃除してから 503 で断る。

## デプロイ（サンプル）

`deploy/` は実環境の値を含まない汎用サンプル。

- `deploy/drop.service` — systemd unit。`DynamicUser`、loopback 待ち受け、swap・コアダンプ無効化、サンドボックス設定。
- `deploy/drop.duxca.com.nginx.conf` — nginx vhost。公開ポートへの中継のみ、`/admin` は 404、ボディ 16 KiB、ログはパスまで。
- `deploy/install.sh` — `sudo ./install.sh <staging-dir>`。staging-dir に `drop`（バイナリ）と `drop.service`、任意で `runtime.env` を置く。変更があったときだけ再起動し、公開ポートで `/` と `/admin/drops` が 404 になることを確認する。nginx には触らない。

admin ポートは nginx からもトンネルからも出さない。admin を叩くのは同じホスト上のプロセスだけにする。

## 開発・テスト

```sh
cargo test                # store / token / config の単体テストと、HTTP の振る舞い（tower::ServiceExt::oneshot）
cargo build --release     # target/release/drop
cargo audit               # 依存の既知脆弱性

cp .env.example .env
cargo run                 # 127.0.0.1:8470（公開）と 127.0.0.1:8471（admin）。Ctrl+C / SIGTERM で graceful shutdown
```

構成:

| ファイル | 役割 |
|---|---|
| `src/main.rs` | 起動、2 つのリスナー、定期パージ、Ctrl+C / SIGTERM での graceful shutdown |
| `src/config.rs` | `DROP_*` 環境変数（envy）と検証 |
| `src/token.rs` | トークン生成（OS CSPRNG 128bit）と正規形の検証 |
| `src/store.rs` | メモリ内ストア（TTL、1 回書き込み・1 回読み出し、上限） |
| `src/public.rs` | 公開側ルータ（フォーム、投稿、take） |
| `src/admin.rs` | admin 側ルータ（発行、破棄、Host 検査） |
| `src/web.rs` | 共有: 状態、セキュリティヘッダ、404、HTML エスケープ |
| `src/tests.rs` | HTTP の結合テスト |

tokio は `current_thread`。状態は `Arc<Mutex<Store>>` 1 つ（axum のハンドラが `Send` を要求するため Mutex で包むが、ロックは await をまたがない）。
