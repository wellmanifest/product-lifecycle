FROM python@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419

WORKDIR /workspace
COPY standard/ standard/

USER 65532:65532
ENTRYPOINT ["python3", "standard/conformance.py", "--all"]
