# AdScan — tek komutla tekrarlanabilir ortam.
# Build:  docker build -t adscan .
# Çalıştır: docker run --rm -it --network host adscan 10.10.10.0/24 --full --html
#   (--network host: hedefe doğrudan erişim; raporları almak için -v $PWD/out:/out
#    ekleyip --outdir /out verin.)
FROM python:3.12-slim

# Harici CLI araçları (adscan stdlib-only; bunlar PATH'te olmalı)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap dnsutils ldap-utils krb5-user smbclient \
        git curl ca-certificates pipx \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.local/bin:${PATH}"

# netexec (nxc), certipy, bloodyAD, impacket — izole pipx ortamlarında
RUN pipx install git+https://github.com/Pennyw0rth/NetExec.git \
    && pipx install certipy-ad \
    && pipx install bloodyAD \
    && pipx install impacket

WORKDIR /opt/adscan
COPY . /opt/adscan
RUN pip install --no-cache-dir -e .

# Konteyner içinde onay istemini atlamadan çalışması için --yes önerilir (yetkili ortam!)
ENTRYPOINT ["python", "-m", "adscan"]
CMD ["--check"]
