# CodeAlpha_Task1-NetworkSniffer

# 🚀 Task 1 – Basic Network Sniffer

## 📌 Overview
This project implements a **Python-based network sniffer** that captures and analyzes packets in real-time.  
It extracts useful details (source IP, destination IP, protocol, payload size), logs them into a **CSV file**,  
and visualizes live traffic distribution using **Matplotlib**.

## 🛠️ Features
- Capture live packets with **Scapy**
- Extract and display:
  - Source IP
  - Destination IP
  - Protocol (TCP, UDP, ICMP, Other)
  - Payload Size
  - Timestamp
- Save captured packets into **CSV (`packet_logs.csv`)**
- Generate **Excel-based analysis** with charts
- Show a **live updating graph** of protocol distribution

## 📂 Project Structure


## ▶️ How to Run
1. Install dependencies:
   ```bash
   pip install scapy prettytable matplotlib

Run...
python sniffer.py
