FROM python

WORKDIR /app/

RUN python3 -m pip install cloudone-vsapi

COPY scanner.py /app/

ENTRYPOINT [ "python3", "scanner.py" ]