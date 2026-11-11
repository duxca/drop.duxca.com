#!/usr/bin/env bash
# drop を対象ホストに入れる（汎用サンプル）。対象ホスト上で sudo 実行する。
#   sudo ./install.sh <staging-dir>
# staging-dir には drop（リリースビルドのバイナリ）と drop.service、
# 任意で runtime.env（DROP_* の上書き。秘密は不要）を置く。
# nginx の vhost は環境ごとに手で入れる（drop.duxca.com.nginx.conf を参照）。このスクリプトは nginx に触らない。
set -euo pipefail
SRC="${1:?staging dir}"
# drop.service / runtime.env の DROP_PUBLIC_ADDR に合わせる（確認用）
PUBLIC_PORT="${PUBLIC_PORT:-8470}"

install -d -m 755 /opt/drop/bin
install -d -m 700 /etc/drop

# 変わったものだけ再起動する。再起動すると預かり中のドロップは全部消える。
# 上書き前に変更を検出する。宛先が無ければ cmp は失敗する = 変更ありとして扱う。
restart=0
changed() { ! cmp -s "$1" "$2"; }
changed "$SRC/drop" /opt/drop/bin/drop && restart=1
changed "$SRC/drop.service" /etc/systemd/system/drop.service && restart=1
[[ -s "$SRC/runtime.env" ]] && changed "$SRC/runtime.env" /etc/drop/runtime.env && restart=1

install -m 755 "$SRC/drop" /opt/drop/bin/drop
# EnvironmentFile は systemd（root）が読むので、サービス側（DynamicUser）に読ませる必要はない
if [[ -s "$SRC/runtime.env" ]]; then install -m 600 "$SRC/runtime.env" /etc/drop/runtime.env; fi
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
systemctl is-active drop.service
# 公開ポートにはルートページも admin も無い（どちらも 404）
root=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PUBLIC_PORT}/")
admin=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' \
  "http://127.0.0.1:${PUBLIC_PORT}/admin/drops")
echo "public GET / -> $root, public POST /admin/drops -> $admin"
[[ "$root" == 404 && "$admin" == 404 ]]
