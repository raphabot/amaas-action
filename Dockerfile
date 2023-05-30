FROM python

WORKDIR /app/

COPY am-scanner.py /app/

RUN python3 -m pip install cloudone-vsapi

ENTRYPOINT [ "python3", "am-scanner.py" ]