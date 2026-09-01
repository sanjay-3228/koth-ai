FROM python:3.13-alpine

RUN adduser -D app

WORKDIR /app

COPY app.py .

USER app

EXPOSE 8080

CMD ["python3", "app.py"]
