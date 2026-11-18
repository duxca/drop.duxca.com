#!/usr/bin/env bash
# drop を対象ホストに入れる（汎用サンプル）。対象ホスト上で sudo 実行する。
#   sudo ./install.sh <staging-dir>
# staging-dir には drop（リリースビルドのバイナリ）と drop.service、
# 任意で runtime.env（DROP_* の上書き。秘密は不要）と
# admin-hashes.env（遠隔 admin の検証子。DROP_REMOTE_ADMIN_TOKEN_SHA256S の代入 1 行）を置く。
# nginx の vhost は環境ごとに手で入れる（drop.duxca.com.nginx.conf を参照）。このスクリプトは nginx に触らない。
set -euo pipefail
SRC="${1:?staging dir}"
# drop.service / runtime.env の DROP_PUBLIC_ADDR に合わせる（確認用）
PUBLIC_PORT="${PUBLIC_PORT:-8470}"

# admin-hashes.env は反映前に形式を検証する。不正なら既存の設定には一切触れずに失敗する
# （検証子の形式エラーでサービス全体を落とさないため）。
if [[ -f "$SRC/admin-hashes.env" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      '' | '#'*) ;;
      DROP_REMOTE_ADMIN_TOKEN_SHA256S=*)
        value="${line#DROP_REMOTE_ADMIN_TOKEN_SHA256S=}"
        if [[ -n "$value" && ! "$value" =~ ^[0-9a-fA-F]{64}(,[0-9a-fA-F]{64})*$ ]]; then
          echo "install.sh: admin-hashes.env の検証子が形式不正です" >&2
          exit 1
        fi
        ;;
      *)
        echo "install.sh: admin-hashes.env に想定外の行があります" >&2
        exit 1
        ;;
    esac
  done < "$SRC/admin-hashes.env"
fi

install -d -m 755 /opt/drop/bin
install -d -m 700 /etc/drop

# 戻せるように、置き換える前のファイルを控える。
BACKUP=$(mktemp -d)
backup() {
  if [[ -e "$2" ]]; then
    cp -a "$2" "$BACKUP/$1"
    touch "$BACKUP/$1.existed"
  fi
}
backup drop /opt/drop/bin/drop
backup drop.service /etc/systemd/system/drop.service
backup runtime.env /etc/drop/runtime.env
backup admin-hashes.env /etc/drop/admin-hashes.env

restore() {
  echo "install.sh: 反映後の確認に失敗したため、直前の状態へ戻します" >&2
  local pair name dest
  for pair in "drop:/opt/drop/bin/drop" "drop.service:/etc/systemd/system/drop.service" "runtime.env:/etc/drop/runtime.env" "admin-hashes.env:/etc/drop/admin-hashes.env"; do
    name="${pair%%:*}"
    dest="${pair#*:}"
    if [[ -e "$BACKUP/$name.existed" ]]; then
      install -m "$(stat -c %a "$BACKUP/$name")" "$BACKUP/$name" "$dest" || true
    else
      rm -f "$dest"
    fi
  done
  systemctl daemon-reload || true
  systemctl restart drop.service || true
}

# 変わったものだけ再起動する。再起動すると預かり中のドロップは全部消える。
# 上書き前に変更を検出する。宛先が無ければ cmp は失敗する = 変更ありとして扱う。
restart=0
changed() { ! cmp -s "$1" "$2"; }
changed "$SRC/drop" /opt/drop/bin/drop && restart=1
changed "$SRC/drop.service" /etc/systemd/system/drop.service && restart=1
[[ -s "$SRC/runtime.env" ]] && changed "$SRC/runtime.env" /etc/drop/runtime.env && restart=1
[[ -f "$SRC/admin-hashes.env" ]] && changed "$SRC/admin-hashes.env" /etc/drop/admin-hashes.env && restart=1

install -m 755 "$SRC/drop" /opt/drop/bin/drop
# EnvironmentFile は systemd（root）が読むので、サービス側（DynamicUser）に読ませる必要はない
if [[ -s "$SRC/runtime.env" ]]; then install -m 600 "$SRC/runtime.env" /etc/drop/runtime.env; fi
if [[ -f "$SRC/admin-hashes.env" ]]; then install -m 600 "$SRC/admin-hashes.env" /etc/drop/admin-hashes.env; fi
install -m 644 "$SRC/drop.service" /etc/systemd/system/drop.service
systemctl daemon-reload
systemctl enable -q drop.service

if ((restart)); then
  systemctl restart drop.service
elif systemctl is-active -q drop.service; then
  echo "drop.service: 変更なし。再起動をスキップ"
else
  systemctl start drop.service
fi

sleep 1
ok=1
systemctl is-active -q drop.service || ok=0
root=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PUBLIC_PORT}/") || root=000
admin=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' \
  "http://127.0.0.1:${PUBLIC_PORT}/admin/drops") || admin=000
api=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' \
  "http://127.0.0.1:${PUBLIC_PORT}/api/drops") || api=000
echo "public GET / -> $root, public POST /admin/drops -> $admin, public POST /api/drops (no auth) -> $api"
[[ "$root" == 404 && "$admin" == 404 && "$api" == 404 ]] || ok=0
if ((ok == 0)); then
  restore
  rm -rf "$BACKUP"
  exit 1
fi
rm -rf "$BACKUP"
