FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=3000 \
    VT_DATABASE=/app/data/history.sqlite3

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY app.py ./
COPY public/ ./public/
RUN mkdir -p /app/data

EXPOSE 3000
CMD ["python", "app.py"]
