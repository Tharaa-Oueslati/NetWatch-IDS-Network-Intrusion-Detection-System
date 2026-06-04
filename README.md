# NetWatch-IDS

## Overview

NetWatch-IDS is a Python-based Intrusion Detection System designed to monitor network traffic and detect malicious activities in real time.

The project was developed to understand how modern Security Operations Centers (SOCs) identify network-based threats and generate actionable alerts.

Unlike traditional academic projects, NetWatch-IDS implements several concepts used by enterprise-grade solutions such as Snort and Suricata.

## Key Features

* Real-time packet capture using Scapy
* Detection of SYN flood attacks
* Port scanning detection
* ARP spoofing detection
* Custom rule engine inspired by Snort
* JSON-based rule configuration
* Web dashboard for alert visualization
* PCAP replay mode for testing
* Dockerized deployment

## Technical Architecture

Traffic is captured through a monitoring interface and processed by the packet analysis engine.

Packets are evaluated against a configurable rule set.

When suspicious behavior is detected:

1. An alert is generated.
2. Alert metadata is stored.
3. The dashboard updates in real time.

## Technologies

* Python
* Scapy
* Flask
* Chart.js
* Docker
* JSON

## Learning Outcomes

This project demonstrates understanding of:

* Network protocols
* Intrusion detection systems
* Security monitoring
* Packet analysis
* DevSecOps deployment practices
