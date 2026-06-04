FROM python:3.11-slim

# System deps for Scapy (raw sockets, libpcap)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate sample PCAP for demo mode
RUN python pcap_samples/generate_sample_pcap.py || true

EXPOSE 5000

# NET_ADMIN + NET_RAW needed for live capture
# In demo/replay mode these are not required
CMD ["python", "dashboard/app.py"]
