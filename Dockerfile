# The scanner image: each repo is scanned in a fresh, read-only container from it
# (see scan_repo in verify_service.py), so a model that exploited the scanner could not
# reach another repo's verdict, the workflow's environment, or the next scan.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
COPY requirements.txt /requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes --no-deps -r /requirements.txt
USER 65534:65534
ENTRYPOINT ["python", "-m", "hayward"]
