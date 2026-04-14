# EVTX Log Documentation Framework
This documentation organizes Windows Event Logs (EVTX) into noise tiers, defines their typical contents, highlights critical logs for security monitoring, and provides a rapid baseline framework for triage. It is based on authoritative sources such as Microsoft guidance and the MITRE ATT&CK framework.

## Three-Circle Categorization of EVTX Logs

Inner Circle (Most Noisy): Logs that generate a high volume of events, often including routine system and application activity. These logs require careful filtering to reduce noise.
Middle Circle (Moderately Noisy): Logs with moderate event volume that contain valuable security-relevant information.
Outer Circle (Least Noisy): Logs with low event volume but high importance for detecting critical security events.

<table border="1" cellspacing="0" cellpadding="6">
  <thead>
    <tr>
      <th>Log Name</th>
      <th>Noise Tier</th>
      <th>Security Relevance</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Security</td>
      <td>Inner Circle</td>
      <td>High</td>
      <td>Contains security-related events such as logon/logoff, account management, and policy changes.</td>
    </tr>
    <tr>
      <td>System</td>
      <td>Inner Circle</td>
      <td>Medium</td>
      <td>Records system-level events including driver and service status.</td>
    </tr>
    <tr>
      <td>Application</td>
      <td>Inner Circle</td>
      <td>Low</td>
      <td>Logs application-specific events; noise depends on installed software.</td>
    </tr>
    <tr>
      <td>Microsoft-Windows-PowerShell/Operational</td>
      <td>Middle Circle</td>
      <td>High</td>
      <td>Tracks PowerShell activity, useful for detecting script-based attacks.</td>
    </tr>
    <tr>
      <td>Microsoft-Windows-Sysmon/Operational</td>
      <td>Middle Circle</td>
      <td>High</td>
      <td>Provides detailed system monitoring, including process creation and network connections.</td>
    </tr>
    <tr>
      <td>Windows Defender/Operational</td>
      <td>Outer Circle</td>
      <td>High</td>
      <td>Logs Windows Defender antivirus events.</td>
    </tr>
  </tbody>
</table>


## Descriptions of Key Logs
### Security Log
    Contents: Authentication events, user account changes, privilege use.
    Why Monitor: Essential for detecting unauthorized access and privilege escalation.

### System Log
    Contents: System startup/shutdown, driver and service events.
    Why Monitor: Useful for identifying system stability issues and suspicious service behavior.

### PowerShell Operational Log
    Contents: PowerShell command execution and script block logging.
    Why Monitor: Critical for detecting malicious PowerShell activity.

### Sysmon Operational Log
    Contents: Detailed process creation, network connections, file creation, and registry changes.
    Why Monitor: Provides deep visibility into system behavior for advanced threat detection.

### Windows Defender Operational Log
    Contents: Antivirus detections, scan results, and remediation actions.
    Why Monitor: Important for endpoint protection status and malware detection.

### Baseline Framework for Rapid Analysis
    Filtering: Use noise tier categorization to apply filters that reduce irrelevant events.
    Prioritization: Focus on logs with high security relevance and critical event IDs such as 4624 (Logon), 4625 (Failed Logon), 4688 (Process Creation), 7045 (Service Installation), and 1102 (Audit Log Clear).
    Well-Known Event IDs for First Priority Look:
        4624: Successful Logon
        4625: Failed Logon
        4688: Process Creation
        4697: Service Installation
        1102: Audit Log Clear
        7045: New Service Installed
        4720: User Account Created
        4726: User Account Deleted
        4732: Member Added to Security-Enabled Local Group
        4672: Special Privileges Assigned to New Logon

#### Additional Well-Known Event IDs to Consider:
        4648: Logon Using Explicit Credentials
        4657: Registry Value Modified
        4663: Object Access (File/Folder)
        4689: Process Termination
        4698: Scheduled Task Created
        4699: Scheduled Task Deleted
        4776: Credential Validation
        4781: Account Name Changed
        4798: User's Local Group Membership Enumerated
        5140: Network Share Object Access
        5156: Windows Filtering Platform Connection Allowed
        5158: Windows Filtering Platform Connection Blocked
        8004: Windows Defender Antivirus Detection
        1100: Audit Policy Change

### This expanded list helps cover more critical activities and potential indicators of compromise for first-priority filtering and analysis.

    Mapping to ATT&CK: Correlate events with MITRE ATT&CK techniques to identify attacker behaviors.
    Automation: Implement scripted parsing and alerting based on the baseline framework.
    Filtering: Use noise tier categorization to apply filters that reduce irrelevant events.
    Prioritization: Focus on logs with high security relevance and critical event IDs.
    Mapping to ATT&CK: Correlate events with MITRE ATT&CK techniques to identify attacker behaviors.
    Automation: Implement scripted parsing and alerting based on the baseline framework




