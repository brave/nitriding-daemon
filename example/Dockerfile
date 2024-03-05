# A Go base image is enough to build nitriding reproducibly.
# We use a specific instead of the latest image to ensure reproducibility.
FROM golang:1.20 as builder

WORKDIR /

# Clone the repository and build the stand-alone nitriding executable.
RUN git clone https://github.com/brave/nitriding-daemon.git
ARG TARGETARCH
RUN ARCH=${TARGETARCH} make -C nitriding-daemon/ nitriding

# Use the intermediate builder image to add our files.  This is necessary to
# avoid intermediate layers that contain inconsistent file permissions.
COPY service.py start.sh /bin/
RUN chown root:root /bin/service.py /bin/start.sh
RUN chmod 0755      /bin/service.py /bin/start.sh

FROM python:3.11-slim-bullseye

# Copy all our files to the final image.
COPY --from=builder /nitriding-daemon/nitriding /bin/start.sh /bin/service.py /bin/

CMD ["start.sh"]
