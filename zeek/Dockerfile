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
# proper DNP3, S7comm, and BACnet logging with far more granular
# fields (dedicated modbus.log / dnp3.log / s7comm.log / bacnet.log
# instead of everything folding into conn.log's generic "service"
# field). Each install is best-effort, same pattern as before -
# a network hiccup during build shouldn't break the whole image.
# ---------------------------------------------------------------
RUN zkg autoconfig --force || true
RUN zkg install --force cisagov/icsnpp-modbus || echo "icsnpp-modbus install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-dnp3 || echo "icsnpp-dnp3 install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-s7comm || echo "icsnpp-s7comm install skipped - add manually if needed"
RUN zkg install --force cisagov/icsnpp-bacnet || echo "icsnpp-bacnet install skipped - add manually if needed"

WORKDIR /usr/local/zeek

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
