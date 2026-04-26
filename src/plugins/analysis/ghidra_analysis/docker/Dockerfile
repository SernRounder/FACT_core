# Dockerfile for the FACT_core ghidra_analysis plugin
#
# Builds a minimal image containing:
#   * OpenJDK 21 (required by Ghidra 12.x)
#   * Ghidra (downloaded from the official GitHub release)
#   * Python 3 + pyghidra (Python bridge for Ghidra scripting)
#
# The image exposes no ports and is only used in headless / batch mode.

FROM eclipse-temurin:21-jdk-jammy

# Keep these args together so the downloaded archive is explicit and reproducible.
ARG GHIDRA_VERSION=12.0.4
ARG GHIDRA_DATE=20260303

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

RUN apt-get update && \
    apt-get install -y --no-install-recommends wget unzip python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN GHIDRA_ARCHIVE="ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" && \
    wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ARCHIVE}" \
        -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" "${GHIDRA_INSTALL_DIR}" && \
    rm /tmp/ghidra.zip

# pyghidra requires this bundled Ghidra feature at runtime.
RUN test -f /opt/ghidra/Ghidra/Features/PyGhidra/lib/PyGhidra.jar

# Install pyghidra - the Python bridge for Ghidra's Java API (via jpype)
RUN pip3 install --no-cache-dir pyghidra

# Create a non-root user for running analysis
RUN useradd -m -u 1000 ghidra && \
    chown -R ghidra:ghidra /opt/ghidra/support
USER ghidra

WORKDIR /home/ghidra
