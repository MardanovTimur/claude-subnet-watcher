FROM python:3.12-slim

WORKDIR /app
COPY app.py pyproject.toml ./

ENV HTTP_HOST=0.0.0.0 \
    HTTP_PORT=8080 \
    DATA_DIR=/app/data

EXPOSE 8080
VOLUME ["/app/data"]

CMD ["python3", "app.py"]
