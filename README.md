# SIEM Project: Brute-Force / Port Scan Attack Detection

## Context
This project utilizes the Splunk Security Information and Event Management (SIEM) platform to analyze security logs and develop an automated detection rule against brute-force attacks and port scans.

## Objective
To detect source IP addresses (Source_IP) performing an abnormally high number of failed connection attempts or network scans within a limited timeframe.

## Detection Method and Logic

The approach relies on two key steps using the Search Processing Language (SPL):
1. **Field Extraction (REX)**: Extracting the non-indexed source IP address from the raw log data.
2. **Aggregation (STATS)**: Counting the malicious events per IP and applying a dynamic threshold.

## Detection Rule (SPL)

This is the final Search Processing Language (SPL) query used to identify the attackers:

```spl
index=main PortScan OR BotAttack OR Failure
| rex "(?<Source_IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[,\s]"
| stats count as Attack_Count by Source_IP
| where Attack_Count > 5
| sort -Attack_Count
