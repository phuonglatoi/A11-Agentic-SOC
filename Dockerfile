FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home --uid 10001 soc
COPY --chown=soc:soc app ./app
COPY --chown=soc:soc data ./data
COPY --chown=soc:soc knowledge ./knowledge
COPY --chown=soc:soc models ./models
RUN mkdir -p /app/runtime && chown -R soc:soc /app/runtime

USER soc
EXPOSE 8000/tcp 5514/udp
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
