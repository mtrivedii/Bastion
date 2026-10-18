# Builder: install dependencies into an isolated virtualenv.
FROM python:3.14-slim AS builder

WORKDIR /build

RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"

COPY requirements.txt .
# hadolint ignore=DL3013
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip uninstall -y pip setuptools wheel

# Runtime: copy only the venv, nothing else from the build stage.
FROM python:3.14-slim

# Non-root by default -- Phase 2's Kyverno policy blocks root containers,
# so the image needs to already run this way, not be retrofitted later.
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --create-home --shell /usr/sbin/nologin appuser

COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# The runtime image does not need a package manager. Removing pip, setuptools
# and wheel from the base image also removes the libraries they bundle.
RUN /usr/local/bin/python -m pip uninstall -y pip setuptools wheel

WORKDIR /app
COPY app/ ./app/
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# DATABASE_URL is supplied at runtime via a k8s Secret/ConfigMap, never
# baked into the image.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
