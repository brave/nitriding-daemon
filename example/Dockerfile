FROM alpine:latest

RUN mkdir -p /lib64 && ln -sf /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
RUN apk add --no-cache py3-pip
RUN pip install requests

COPY nitriding /
COPY service.py /
COPY start.sh /

CMD ["/start.sh"]
