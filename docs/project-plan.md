# Project Plan

## Title

Real-Time Insider Threat Detection Using Network Behavior Profiling

## Problem Statement

Traditional security tools often focus on known attack signatures. Insider threats are harder to detect because malicious activity may come from valid accounts inside the network. This project aims to detect such threats by learning normal user network behavior and identifying anomalies in real time.

## Objectives

- Build a user behavior profiling system from network events
- Detect abnormal behavior patterns in real time
- Generate interpretable alerts with reasons
- Demonstrate the solution using simulated network activity

## Proposed Inputs

Each network event may include:

- Timestamp
- User ID
- Source IP
- Destination IP
- Protocol
- Bytes sent
- Bytes received
- Action type

## Core Features

- Login hour deviation
- New destination access
- New source IP
- Traffic spike detection
- Sudden increase in frequency

## Methodology

1. Generate or collect network activity logs
2. Group events by user
3. Maintain a baseline profile for each user
4. Score each new event against that profile
5. Trigger an alert when the score crosses a threshold

## Tools and Technologies

- Python
- CSV or JSON event data
- Optional later: pandas, scikit-learn, matplotlib, Streamlit

## Evaluation Ideas

- Number of true suspicious events detected
- False positive rate
- Alert explanation quality
- Runtime suitability for near real-time use

## Extension Ideas

- Add machine learning models
- Use real public cybersecurity datasets
- Build a web dashboard
- Add threat severity categories
- Compare rule-based and ML-based detection
