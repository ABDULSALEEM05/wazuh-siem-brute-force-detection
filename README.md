# wazuh-siem-brute-force-detection
Wazuh SIEM custom threshold alerting (Rule 100201 / MITRE ATT&amp;CK T1110) and SOC dashboard deployment on Ubuntu 22.04 LTS with live trigger verification.
# Wazuh SIEM Custom Threshold Alerting & SOC Dashboard Deployment

End-to-end configuration, visualization engineering, and empirical trigger verification of **Custom Rule `100201` (MITRE ATT&CK `T1110` – Brute Force)** on **Ubuntu 22.04 LTS** using Wazuh Manager and OpenSearch Dashboards.

> **Download Full Formal Report:** [Wazuh_SIEM_Alert_Configuration_and_Trigger_Report.pdf](docs/Wazuh_SIEM_Alert_Configuration_and_Trigger_Report.pdf)

---

## Lab Specifications & Summary

| Parameter | Configuration Details |
| :--- | :--- |
| **Target Host** | Ubuntu 22.04 LTS (`UBUNTU`) |
| **SIEM Platform** | Wazuh Manager & OpenSearch Dashboards |
| **Custom Rule ID** | `100201` (Severity Level `10`) |
| **Parent Rule ID** | `5503` (PAM: User login failed) |
| **Correlation Logic** | `frequency="5"` within `timeframe="600"` (10 minutes) |
| **MITRE ATT&CK Mapping** | `T1110` (Brute Force / Credential Access) |
| **Custom Dashboard** | `Ubuntu Security Operations Dashboard` |

---

## 1. SOC Visualization & Dashboard Architecture

A custom two-panel dashboard (**Ubuntu Security Operations Dashboard**) was built on the `wazuh-alerts-*` index pattern to correlate authentication failure spikes with adversarial tactics:

* **Panel 1 — Failed Logins Over Time (Line Chart):** Filtered via DQL `rule.id: "5503"` across 30-second `@timestamp` intervals to track brute-force velocity.
* **Panel 2 — Top Security Techniques (Donut Chart):** Aggregated by `rule.mitre.technique` (`Terms` ordered by `Count`) to classify active MITRE ATT&CK techniques (*Valid Accounts*, *Sudo and Sudo Caching*, *Password Guessing*, etc.).

![Ubuntu Security Operations Dashboard](screenshots/Screenshot 2026-11-12 072613)

---

## 2. Custom Alert Rule Engineering (`local_rules.xml`)

To prevent alert fatigue from single benign login typos while catching sustained password-guessing attempts, stateful correlation **Rule `100201`** was deployed in `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="linux, authentication, lab_alerts">
  <rule id="100201" level="10" frequency="5" timeframe="600">
    <if_matched_sid>5503</if_matched_sid>
    <description>High frequency failed logins detected: >5 failures in 10 minutes.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
