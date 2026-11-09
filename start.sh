#!/bin/bash
set -e

cd /home/airi/1xbts

# Enable packet-layer capture only when the caller explicitly provides a
# destination. This leaves the normal startup path unchanged while making a
# synchronized PPP/RLP investigation repeatable without editing config files.
if [ -n "${CDMA_PACKET_CAPTURE_DIR:-}" ]; then
    mkdir -p "$CDMA_PACKET_CAPTURE_DIR"
    export CDMA_PACKET_CAPTURE="${CDMA_PACKET_CAPTURE:-1}"
fi

# Load required kernel modules
sudo modprobe fou
sudo modprobe ipip

# Configure the host networking first
sudo ./docker/femto/host-route.sh add

# Start the complete CDMA core
exec ./target/release/cdma-nib \
    --config-dir config \
    --component cdma-hlr \
    --component cdma-smsc \
    --component cdma-events \
    --component cdma-pdsn \
    --component cdma-msc
