#playwright's own image, it has chromium and its system libraries but NOT the python
#package, that gets installed below. the tag and the pip version have to match or the
#python package would look for a different chromium build than the one in the image
FROM mcr.microsoft.com/playwright/python:v1.64.1-noble

#iptables is only needed by the entrypoint to lock the network down
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

#--break-system-packages is fine here, this image only exists to run one script
RUN pip install --no-cache-dir --break-system-packages playwright==1.64.1

COPY fetch.py entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

#starts as root on purpose, entrypoint.sh sets the firewall and then drops to pwuser
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python3", "/app/fetch.py"]
