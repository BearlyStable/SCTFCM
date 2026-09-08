FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY src/app.py .
COPY src/templates/ templates/
COPY src/static/ static/

RUN mkdir -p instance

EXPOSE 5050

CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:5050", "--timeout", "120", "app:app"]
