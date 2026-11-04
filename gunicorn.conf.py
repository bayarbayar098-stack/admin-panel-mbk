# gunicorn тохиргоо (gunicorn энэ файлыг автоматаар уншина)
import os

# Render PORT хувьсагчаар портыг өгдөг
bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"

# Сесс санах ойд хадгалагддаг тул ЗААВАЛ 1 worker.
# Олон зэрэг хүсэлтийг thread-ээр зохицуулна.
workers = 1
threads = 8
worker_class = "gthread"
timeout = 60

# Хүсэлт бүрийг апп өөрөө (query-гүйгээр) log хийдэг тул gunicorn-ы access log унтраалттай
accesslog = None
errorlog = "-"
loglevel = "info"
