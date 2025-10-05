FROM python:3.11-slim

RUN pip install --upgrade pip

RUN pip install flask requests

WORKDIR /app

COPY . .

EXPOSE ${PORT}

CMD ["python3", "evolute_api.py"]
