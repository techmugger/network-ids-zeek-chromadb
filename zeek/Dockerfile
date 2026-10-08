FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------
# Install Zeek from the official OpenSUSE Build Service repo
# (this is the standard supported way to get Zeek on Ubuntu)
# ---------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        gnupg2 \
        ca-certificates \
        ethtool \
        iproute2 \
        net-tools \
        python3 \
        python3-pip \
    && curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
        | gpg --dearmor -o /usr/share/keyrings/zeek-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
        > /etc/apt/sources.list.d/security:zeek.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends zeek \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/zeek/bin:/usr/local/zeek/bin:${PATH}"

# Zeek installs to /opt/zeek on this repo; symlink for consistency
RUN ln -s /opt/zeek /usr/local/zeek || true

# ---------------------------------------------------------------
# Build tools. Most ICSNPP packages compile a Spicy analyzer during
# `zkg install`, which needs CMake and a C++ toolchain. The Zeek 9
# package is configured to use /usr/bin/g++-12 specifically, so
# g++-12 is required (Ubuntu 22.04's default g++ is 11, which is not
# enough for the packages that compile at install time).
# ---------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        g++ \
        g++-12 \
        make \
        git \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------
# OT/ICS protocol support: Zeek ships a bare-bones Modbus analyzer
# built in. CISA/INL's ICSNPP packages replace/extend it and add
# proper per-protocol logging (dedicated modbus.log / dnp3.log /
# s7comm.log / bacnet.log / etc. instead of everything folding into
# conn.log's generic "service" field).
#
# Covers: Modbus, DNP3, S7comm/S7comm-plus, BACnet, EtherNet/IP+CIP,
# EtherCAT, GE-SRTP, Genisys, OPC UA (binary), PROFINET I/O context
# manager, Synchrophasor (IEEE C37.118), and BSAP.
#
# Each install loop tries every package in its group, prints the zkg
# build log for any that fail, and FAILS THE BUILD if any package is
# missing, so a broken install can no longer hide behind a
# "successful" image. Packages are split into separate RUN steps so
# earlier groups stay cached if a later one needs another fix.
#
# NOT covered by any ICSNPP (or other Zeek) parser as of writing:
# IEC 60870-5-104, HART-IP, ICCP/TASE.2, IEC 61850 (GOOSE/MMS), and
# OPC DA/UA-over-HTTPS. If the SCADA lab testbed runs any of these,
# Zeek will still log the raw TCP conversation in conn.log (and
# ingest.py/sniffer_agent.py classify it OT by port - see their
# OT_PORTS comments) but without deep per-field parsing. Confirm this
# against real testbed traffic and open an issue with CISA, or add a
# Spicy grammar yourself, if deep parsing of one of these turns out
# to matter for your SCADA lab specifically.
# ---------------------------------------------------------------
RUN zkg autoconfig --force || true

# Group 1: packages that build without g++-12 specifics
RUN failed=""; \
    for p in modbus dnp3 s7comm bacnet enip ethercat opcua-binary bsap; do \
      echo "=== installing icsnpp-$p ==="; \
      zkg install --force cisagov/icsnpp-$p || { \
        failed="$failed $p"; \
        echo "--- build log for icsnpp-$p ---"; \
        tail -40 /opt/zeek/var/lib/zkg/logs/icsnpp-$p-build.log 2>/dev/null || true; }; \
    done; \
    echo "FAILED PACKAGES (group 1):[$failed]"; \
    [ -z "$failed" ]

# Group 2: packages that need g++-12 to compile their analyzers
RUN failed=""; \
    for p in ge-srtp genisys synchrophasor; do \
      echo "=== installing icsnpp-$p ==="; \
      zkg install --force cisagov/icsnpp-$p || { \
        failed="$failed $p"; \
        echo "--- build log for icsnpp-$p ---"; \
        tail -40 /opt/zeek/var/lib/zkg/logs/icsnpp-$p-build.log 2>/dev/null || true; }; \
    done; \
    echo "FAILED PACKAGES (group 2):[$failed]"; \
    [ -z "$failed" ]


# Smoke test: fail the build if any installed analyzer can't load.
RUN zkg list && zeek -e 'event zeek_init() { print "ZEEK_LOAD_OK"; }'
WORKDIR /usr/local/zeek

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]