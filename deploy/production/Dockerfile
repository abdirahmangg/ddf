FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN groupadd --system ddf \
    && useradd --system --gid ddf --uid 10001 ddf

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY alembic ./alembic
COPY alembic.ini ./

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[production,openfga]"

RUN mkdir -p /tmp/ddf \
    && chown -R ddf:ddf /tmp/ddf /app

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "ddf.main:app", "--host", "0.0.0.0", "--port", "8000"]
