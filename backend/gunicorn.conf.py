"""
gunicorn 設定

bind 先は .env の FLASK_HOST / FLASK_PORT から読む（app.py と同じ値を使う）。
起動: cd backend && gunicorn -c gunicorn.conf.py app:app
"""
import os
from dotenv import load_dotenv

load_dotenv()

bind = f"{os.environ.get('FLASK_HOST', '127.0.0.1')}:{os.environ.get('FLASK_PORT', '8001')}"

# worker は 1 プロセス固定にする。
# GeoIP キャッシュは SQLite なので複数 worker でも共有されるが、キャッシュにない IP を
# 複数 worker が同時に問い合わせると ip-api.com の無料枠（batch は毎分 15 リクエスト）を無駄に消費する。
# 管理画面の同時アクセスは少ないため、同時リクエストはスレッドで捌く
# （fail2ban-client / iptables-save の呼び出しは I/O 待ちが中心）。
workers = 1
worker_class = "gthread"
threads = 4

# fail2ban-client / iptables-save / grep の subprocess は最大 30 秒待つため、それより長く取る。
# nginx 側の proxy_read_timeout (60s) と揃えている。
timeout = 60
# 停止時に worker が処理中リクエストを終えるまで待つ秒数。systemd の TimeoutStopSec (15s) より短くする。
graceful_timeout = 10
keepalive = 5

# ログは journald に流す（systemd 経由で起動する前提）
accesslog = None
errorlog = "-"
loglevel = "info"
