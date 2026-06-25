# Dockerfile for a small Python web service.
#
# BUGS:
#   1. Uses :latest tag — image is non-reproducible across rebuilds
#   2. Runs as root — anything the container does has root privileges
#   3. ADD instead of COPY for local files (ADD also auto-extracts and
#      fetches from URLs — wider surface than needed)
#   4. apt-get install without --no-install-recommends (bloats image)
#   5. No HEALTHCHECK directive

FROM python:latest

ADD requirements.txt /app/requirements.txt
ADD app.py /app/app.py

WORKDIR /app

RUN apt-get update && apt-get install -y curl
RUN pip install -r requirements.txt

EXPOSE 8000

CMD ["python", "app.py"]
