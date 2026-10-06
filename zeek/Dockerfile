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
        tcpreplay \
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
# OT/ICS protocol support: Zeek ships a bare-bones Modbus analyzer
# built in. CISA/INL's ICSNPP packages replace/extend it and add
# proper per-protocol logging (dedicated modbus.log / dnp3.log /
# s7comm.log / bacnet.log / etc. instead of everything folding into
# conn.log's generic "service" field). Each install is best-effort,
# same pattern as before - a network hiccup, or one package not
# existing for this Zeek version, shouldn't break the whole image.
#
# This is the full published ICSNPP set as of writing (see
# https://github.com/cisagov/ICSNPP and packages.zeek.org) plus
# requires_spicy for the two that need the Spicy parser toolkit.
# Covers: Modbus, DNP3, S7comm/S7comm-plus, BACnet, EtherNet/IP+CIP,
# EtherCAT, GE-SRTP, Genisys, OPC UA (binary), PROFINET I/O context
# manager, Synchrophasor (IEEE C37.118), and BSAP.
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
RUN zkg install --force cisagov/icsnpp-modbus       || echo "icsnpp-modbus install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-dnp3         || echo "icsnpp-dnp3 install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-s7comm       || echo "icsnpp-s7comm install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-bacnet       || echo "icsnpp-bacnet install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-enip         || echo "icsnpp-enip (EtherNet/IP+CIP) install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-ethercat     || echo "icsnpp-ethercat install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-ge-srtp      || echo "icsnpp-ge-srtp install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-genisys      || echo "icsnpp-genisys install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-opcua-binary || echo "icsnpp-opcua-binary install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-profinet-io-cm || echo "icsnpp-profinet-io-cm install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-synchrophasor || echo "icsnpp-synchrophasor install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-bsap         || echo "icsnpp-bsap install skipped - add manually if needed"

WORKDIR /usr/local/zeek

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
