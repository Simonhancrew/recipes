FROM python:3.10-slim

WORKDIR /app

RUN pip install -i https://mirrors.aliyun.com/pypi/simple --upgrade pip

RUN pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple ollama

COPY benchmark.py .

CMD ["python", "benchmark.py"]