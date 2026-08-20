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
# OT/ICS protocol support: Zeek ships Modbus support built in.
# For DNP3 / S7comm / EtherNet-IP, install community packages via
# zkg (Zeek's package manager).
# ---------------------------------------------------------------
RUN zkg autoconfig --force || true
RUN zkg install --force cybera/zeek-dnp3 || echo "dnp3 plugin install skipped - add manually if needed"

WORKDIR /usr/local/zeek

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
