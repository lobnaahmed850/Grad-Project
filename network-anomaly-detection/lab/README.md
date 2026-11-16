# Isolated test lab

Two subnets of Linux hosts joined by two OSPF routers, running in Docker. It follows the layout of the team's GNS3 lab, using open-source parts in place of the licensed Cisco images. Several clients generate normal traffic from both subnets, and an `attacker` host runs the security-testing tools.

```
 lan_a (10.10.1.0/24)                        lan_b (10.10.3.0/24)
 server-a  client-a1  client-a2  attacker    server-b  client-b1
   .10       .20        .21       .11           .10       .20
     \_________\__________\__________\            \_________\
                     r1 ==== core link ==== r2
                              |
                           capture   (sniffs the monitored r1-r2 link)
```

Every network is `internal`, so the lab has no route to your LAN or the internet.

## Use it

Run these from this folder:

```bash
docker compose up -d --build
./set_link.sh                        # 250 microseconds each way, 100 Mbit
./capture_benign.sh my_capture 20    # Writes captures/my_capture.pcap
./capture_profiles.sh 200            # benign_lan, benign_wan and benign_slow at three link speeds
docker compose down                  # Stop the lab
```

Run `set_link.sh` again after every `docker compose up`. Besides setting the link speed, it turns off segmentation offload. With offload on, virtual interfaces merge packets, and captures show 50 KB "packets" that never appear on a real network.

Before trusting a new capture, check that its largest packet is about 1,500 bytes or less and that its traffic mix varies.

## Generate attacks

```bash
./attack_traffic.sh attack_lan   # scan, HTTP flood, SYN flood against server-b:8080
./slow_attacks.sh attack_lan     # slowloris (slow-HTTP DoS) and a wrk high-concurrency flood
```

This runs three bounded attacks from server-a against server-b with standard published tools —
`nmap` (port scan), `nping` (a SYN flood spread across many source ports) and `curl` (an HTTP flood) —
and captures each on the same `r1-r2` link as the benign traffic. It is safe to run only because the
lab is isolated (`internal` networks, the lab's own container as the target) and each attack is
bounded to a fixed count. This is how CICIDS2017 itself was made, so the test matches the training
data; all attacks target the live service on port 8080. A separate Debian `attacker` container
(`attacker.Dockerfile`, `10.10.1.11`) adds `slowhttptest` (the slowloris / GoldenEye slow-HTTP class)
and `wrk` (high-concurrency flood), which the Alpine image could not provide.

With matched normal and attack captures on one network you can ask the two questions that matter:

```bash
# Detection and false alarms on ONE network
python tools/lab_retrain_check.py --csv-dir data/raw/MachineLearningCVE \
    --benign lab/captures/benign_lan.pcap lab/captures/benign_wan.pcap lab/captures/benign_slow.pcap \
    --attack "PortScan=lab/captures/attack_lan_scan.pcap" "SYN flood=lab/captures/attack_lan_synflood.pcap" \
             "HTTP flood=lab/captures/attack_lan_httpflood.pcap" \
    --saved-if models/candidates/if_portable_timing_65536.joblib --out reports/lab_retrain_detector.json
```

## Test a capture

Run this from `network-anomaly-detection/`:

```bash
python tools/test_capture.py lab/captures/my_capture.pcap \
    --if-model models/iforest_v0.1.0.joblib \
    --rf-model models/random_forest_final.joblib
```

It extracts the flows, checks them against the feature contract, and scores the same packets through the old and fixed extraction. It reports the saved models and the chosen design.

To test whole pipelines, `tools/mixed_check.py` scores the lab captures per link speed and traffic type. It then mixes them with real attack flows from the public Friday capture, keeping only attack flows that the models held out of training.

## Limits

The lab's normal traffic is scripted — browsing, downloads, API calls, DNS and SSH — so it doesn't represent real users. Hosts run Alpine Linux, so TCP window and header values differ from the team's Red Hat and Windows VMs, and the Docker links have their own timing. A detector trained on this lab may therefore not transfer to the real deployment network; the lab is for controlled experiments, and the data that fixes the deployed model should come from a network that looks like production.

The attacks (`attack_traffic.sh`) and the normal traffic are now captured on the **same** network, which is what retraining needs. But both are still scripted and bounded, so detection and false-alarm figures from the lab show direction, not real-world accuracy.
