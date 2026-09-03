# Builds the batch loader and the ingest API from one image -- they are the
# same package (graphload/, catalog/, ingest/), just two different
# entrypoints. Build context is this directory, not the repo root: the image
# ships code only, never the preprocessed data or the repo-root .env.
#
#     docker build -t trace-loader .
#
#     # the API (needs NEO4J_* in the environment; see docker-compose.yml)
#     docker run --rm -p 8000:8000 --env-file ../.env trace-loader
#
#     # the batch loader -- data-preprocessing/ and .cache/ are host state,
#     # not image content, so they come in as volumes
#     docker run --rm --env-file ../.env \
#         -v $(pwd)/../data-preprocessing:/app/data-preprocessing:ro \
#         -v $(pwd)/.cache:/app/data-loading/.cache \
#         trace-loader python main.py --check
#
# `docker-compose.yml` wires both of these up for local dev; see its comments
# and ../README.md#adding-a-new-data-source for the cloud/CI shape.

FROM python:3.12-slim

WORKDIR /app/data-loading

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# graphload/config.py's repo_root() walks up two directories from this file
# (data-loading/graphload/config.py -> data-loading -> repo root), so /app has
# to play the part of the repo root inside the container. data-preprocessing/
# is never baked into the image -- it's gitignored, regenerated locally, and
# hundreds of megabytes -- so this just gives the batch-loader mount point
# somewhere to land; the API never reads it and can run without the volume.
RUN mkdir -p /app/data-preprocessing

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

# Binding 127.0.0.1 (ingest/serve.py's own default, correct for a bare-metal
# or SSH-tunnelled deployment) would be unreachable from outside a container
# even with -p published -- Docker's port mapping lands on the container's
# eth0, not its loopback. 0.0.0.0 here is what makes -p work; INGEST_API_KEY
# is what should gate who gets to use that once it's reachable at all.
CMD ["python", "-m", "ingest.serve", "--host", "0.0.0.0"]
