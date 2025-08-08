

FROM python:3.11-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем только необходимые файлы (перед requirements.txt — для использования кэша)
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt


# Копируем остальной код (исключая то, что в .dockerignore)
COPY . .

# Убедимся, что директория instance существует
RUN mkdir -p /app/instance

# Настраиваем скрипт запуска
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Открываем порт
EXPOSE 5000

# Запуск
CMD ["/entrypoint.sh"]
