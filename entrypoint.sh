#!/bin/sh
set -e


if [ ! -f /app/instance/cartridges.db ]; then
  echo "База данных не найдена, создаём..."
  python create_db.py
else
  echo "База данных найдена, пропускаем создание."
fi

exec python app.py
