FROM debian:12-slim
# Standard, published security-testing tools, used ONLY against this lab's own containers on
# internal-only networks to generate labelled attack traffic for the IDS (as CICIDS2017 was made):
#   slowhttptest -> slow-HTTP DoS (the slowloris / GoldenEye class, genuinely distinct from browsing)
#   nmap         -> port scan
#   wrk, apache2-utils (ab) -> high-concurrency HTTP flood
# Debian is used because slowhttptest is not in the Alpine mirror.
RUN apt-get update && apt-get install -y --no-install-recommends \
        slowhttptest nmap wrk apache2-utils curl iproute2 ethtool tcpdump ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY attacker_start.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/attacker_start.sh
ENTRYPOINT ["/usr/local/bin/attacker_start.sh"]
