# --- Builder stage: install dependencies into an isolated virtualenv ---
FROM python:3.12-slim AS builder

WORKDIR /build

RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# --- Final stage: minimal runtime image ---
FROM python:3.12-slim

# Non-root by default -- Phase 2's Kyverno policy blocks root containers,
# so the image needs to already run this way, not be retrofitted later.
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --create-home --shell /usr/sbin/nologin appuser

COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH"

WORKDIR /app
COPY app/ ./app/

USER appuser

EXPOSE 8000

# DATABASE_URL is supplied at runtime via a k8s Secret/ConfigMap, never
# baked into the image.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
