from scapy.all import rdpcap, TCP, IP
import matplotlib.pyplot as plt

PCAP = "lab1.pcap"

# ===== Throughput Calculation =====
def compute_throughput():
    print(f"Reading pcap file: {PCAP} ...\n")
    packets = rdpcap(PCAP)
    if not packets:
        print("No packets found.")
        return [0.0, 0.0]

    flow1_bytes = 0  # TCP on port 7778
    flow2_bytes = 0  # TCP on port 7777

    INF = 10**30
    flow1_start, flow1_end = INF, 0.0
    flow2_start, flow2_end = INF, 0.0

    for packet in packets:
        if TCP not in packet:
            continue
        dport = packet[TCP].dport
        payload_len = len(packet[TCP].payload)
        if payload_len <= 0:
            continue

        t = float(packet.time)
        # Accumulate the payload bytes, Update the time range
        if dport == 7778:
            flow1_bytes += payload_len
            flow1_start = min(flow1_start, t)
            flow1_end = max(flow1_end, t)
        elif dport == 7777:
            flow2_bytes += payload_len
            flow2_start = min(flow2_start, t)
            flow2_end = max(flow2_end, t)

    def calculate_bps(total_bytes, t_start, t_end):
        if t_start == INF or t_end <= t_start:
            return 0.0
        return (total_bytes * 8.0) / (t_end - t_start)

    print("Total bytes result :")
    print(f"Flow1 (TCP on port 7778): {flow1_bytes} Bytes")
    print(f"Flow2 (TCP on port 7777): {flow2_bytes} Bytes\n")

    flow1_bps = calculate_bps(flow1_bytes, flow1_start, flow1_end)
    flow2_bps = calculate_bps(flow2_bytes, flow2_start, flow2_end)

    print("bps result (avg throughput over each flow's active interval):")
    print(f"Flow1 (TCP on port 7778): {flow1_bps:.2f} bps")
    print(f"Flow2 (TCP on port 7777): {flow2_bps:.2f} bps")

    return [flow1_bps, flow2_bps]

def plot_bar(bps):
    flows = [f'Flow1 (TCP 7778)', f'Flow2 (TCP 7777)']
    plt.figure()
    plt.bar(flows, bps, width=0.5, color=['#A6CEE3','#B2DF8A'])
    plt.xlabel('Flows'); plt.ylabel('bps')
    plt.title('Long-term Average Throughput (TCP payload only)')
    plt.tight_layout(); plt.savefig('Throughput.png'); plt.close()

# ===== Packet Gap Analysis =====
def pkt_tuple(pkt):
    return pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport

def is_flow(pkt, flow):
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return False
    t = pkt_tuple(pkt)
    return t == flow or t == (flow[2], flow[3], flow[0], flow[1])

def direction(pkt, flow):
    src, sport, dst, dport = pkt_tuple(pkt)
    return 'forward' if (src == flow[0] and sport == flow[1] and dst == flow[2] and dport == flow[3]) else 'back'

def payload_len(pkt):
    return len(bytes(pkt[TCP].payload))

def analyze_loss_packet():
    flow = ('172.18.0.3', 51414, '172.18.0.2', 7778)

    pkts = rdpcap(PCAP)
    expected_next = None
    print(f"Analyzing packet gaps for flow: {flow} in {PCAP}")
    for idx, pkt in enumerate(pkts, start=1):
        if not is_flow(pkt, flow):
            continue
        direc = direction(pkt, flow)
        tcp = pkt[TCP]
        plen = payload_len(pkt)
        if direc == 'forward' and plen > 0:
            seq_start = tcp.seq
            seq_end = tcp.seq + plen

            if expected_next is None:
                expected_next = seq_end
            else:
                if seq_start > expected_next:
                    print(f"[GAP] frame {idx} : "
                          f"expected {expected_next}, got {seq_start} "
                          f"(gap {seq_start-expected_next} bytes)")
                    expected_next = seq_end
                elif seq_end <= expected_next:
                    print(f"[RETX] frame {idx} : "
                          f"retransmission seq={seq_start}-{seq_end} "
                          f"(len={plen})")
                elif seq_end > expected_next:
                    expected_next = seq_end

                

# ===== Main =====
if __name__ == "__main__":
    bps_a, bps_b = compute_throughput()
    plot_bar([bps_a, bps_b])
    print("Graphs have been saved (Throughput.png).\n")
    analyze_loss_packet()
