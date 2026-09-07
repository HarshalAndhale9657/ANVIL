# ANVIL sealed-exploit sandbox base image.
#
# app/container_runtime.py runs a target app + its exploit together inside a
# `docker run --network none` container built from this image, so the image
# ships the common runtime deps (an app can start with no network at run time).
#
# Build:
#   docker build -t anvil-sandbox:latest -f backend/docker/anvil-sandbox.Dockerfile backend/docker
#
# If Docker Hub layer pulls time out on your network (large-blob / MTU issue),
# fetch the base via a mirror first, then build:
#   docker pull mirror.gcr.io/library/python:3.12-slim
#   docker tag  mirror.gcr.io/library/python:3.12-slim python:3.12-slim
FROM python:3.12-slim

# --retries/--timeout make the install resilient to flaky large-transfer networks.
RUN pip install --no-cache-dir --retries 5 --timeout 60 flask requests

# Non-root user for defense-in-depth inside the sealed container.
RUN useradd -m -u 10001 sandbox
USER sandbox
WORKDIR /work
