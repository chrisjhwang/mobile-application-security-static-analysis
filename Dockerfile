# Full-featured image: scan/batch (androguard), triage (google-genai),
# analyze (pandas/matplotlib, already core), dashboard (streamlit).
FROM python:3.12-slim

WORKDIR /app

# System deps androguard's dependency chain needs to build from source on
# slim images that lack prebuilt wheels for the current platform/arch.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir -e '.[all]'

# Config/results are meant to be mounted in, not baked into the image —
# `apks/` is course-licensed and never ships here (see CLAUDE.md), and
# results/config vary per run.
COPY config.yaml ./

ENTRYPOINT ["mobsec"]
CMD ["--help"]
