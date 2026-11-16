FROM alpine:3.20
RUN apk add --no-cache bind-tools curl dnsmasq ethtool iproute2 iputils nginx openssh python3 tcpdump
# Standard, published security-testing tools, used ONLY against this lab's own containers on
# internal-only networks, to generate labelled attack traffic for the IDS (as CICIDS2017 was made):
#   nmap  -> port scans            nping (ships with nmap) -> bounded SYN floods
RUN apk add --no-cache nmap nmap-nping
# slowhttptest (slow-HTTP DoS, the slowloris/GoldenEye class) is not in every Alpine mirror; take it if present.
RUN apk add --no-cache slowhttptest 2>/dev/null || echo "slowhttptest not in this mirror; skipping"
COPY nginx.conf /etc/nginx/nginx.conf
# A key shared by both lab hosts, so they can open SSH sessions to each other.
# It only works inside this isolated lab.
RUN ssh-keygen -A \
    && mkdir -p /root/.ssh /srv/files/assets \
    && ssh-keygen -q -t ed25519 -N "" -f /root/.ssh/id_ed25519 \
    && cp /root/.ssh/id_ed25519.pub /root/.ssh/authorized_keys \
    && printf 'StrictHostKeyChecking no\nUserKnownHostsFile /dev/null\nLogLevel ERROR\n' > /root/.ssh/config \
    && sed -i 's/^root:!:/root:*:/' /etc/shadow
# Web content: a page, assets of mixed sizes, and downloads from 300 bytes to 20 MB.
RUN cd /srv/files \
    && for size in 300 800 1500 3000 6000 12000 25000 50000 100000 200000 500000 1000000 2000000 5000000 10000000 20000000; do \
         head -c "$size" /dev/urandom > "file_$size.bin"; \
       done \
    && for i in 1 2 3 4 5 6 7 8 9 10 11 12; do \
         head -c "$((i * i * 900))" /dev/urandom > "assets/asset_$i.bin"; \
       done \
    && python3 -c "print('<html><body>' + 'lab page ' * 2000 + '</body></html>')" > index.html
COPY host_start.sh benign_traffic.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/host_start.sh /usr/local/bin/benign_traffic.sh
ENTRYPOINT ["/usr/local/bin/host_start.sh"]
