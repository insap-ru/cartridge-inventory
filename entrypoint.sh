#!/bin/sh
set -e


if [ ! -f /app/instance/cartridges.db ]; then
  echo "���� ������ �� �������, ������..."
  python create_db.py
else
  echo "���� ������ �������, ���������� ��������."
fi

exec python app.py
