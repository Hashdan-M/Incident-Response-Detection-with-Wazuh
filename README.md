<img src="https://github.com/Hashdan-M/Incident-Response-Detection-with-Wazuh/blob/2c7f121347df99bd6fc47a5fe53f3f71089dbd77/Incident%20Response/wazuh-logo.jpg" width=50% height=50%>

# Incident Response Detection with Wazuh

## Overview

In this project, I implemented an Incident Response Plan using **Wazuh**, an open-source security platform, to detect and analyze suspicious activity within a network environment. Specifically, I focused on detecting Indicators of Compromise (IoCs) related to questionable logon activity, as well as identifying anti-forensic activities like log file deletion. This lab is designed to mimic real-world attack scenarios and evaluate how effectively Wazuh can alert administrators to malicious activity.

### Tools Used
- **Wazuh**: An open-source security information and event management (SIEM) solution that integrates with Elastic Stack. It provides threat detection, compliance monitoring, and incident response capabilities.
- **Kali Linux**: A penetration testing and security auditing Linux distribution used for attacking and testing security vulnerabilities.
- **Windows Server 2019 (DC10)**: A Windows domain controller that serves as the target for various attack simulations, including brute-force login attempts and remote share access.
- **Hydra**: A fast and flexible password-cracking tool used to perform dictionary-based password-guessing attacks.

### Objectives
The goal of this project was to:
1. **Detect suspicious logon activity** using Wazuh, specifically:
   - Perform dictionary-based password-guessing attacks against the administrator account.
   - Simulate mounting of Windows shares.
2. **Identify anti-forensic activity**:
   - Simulate log file deletion (as a common anti-forensics technique) and monitor Wazuh’s ability to detect such activity.
3. **Monitor and respond to security alerts** related to these activities.

---

## Step-by-Step Implementation

### 1. **Preparation and Setup**

#### **Step 1: Access Kali Linux (Security Workstation)**
I started by logging into **Kali Linux** as the root user. This machine was used to perform various attack simulations. 

<img src="https://github.com/Hashdan-M/Incident-Response-Detection-with-Wazuh/blob/2c7f121347df99bd6fc47a5fe53f3f71089dbd77/Incident%20Response/1.PNG" width=50% height=50%>

#### **Step 2: Create a Password List for Brute-Force Attack**
I used a popular list of commonly used passwords, `/usr/share/seclists/Passwords/500-worst-passwords.txt`, and modified it to include the password `Pa$$w0rd` at the 57th line. This was done using the `sed` command to inject the password into the file, creating a custom password list (`passlist.txt`) for the brute-force attack. I then entered `ls -l` to confirm the `passlist.txt` is present in the current directory (which should be `/root`). Finally, enter `grep -n 'Pa$$w0rd' passlist.txt`. The output should confirm that `Pa$$w0rd` was added at line 57.

<img src="https://github.com/Hashdan-M/Incident-Response-Detection-with-Wazuh/blob/2c7f121347df99bd6fc47a5fe53f3f71089dbd77/Incident%20Response/2.PNG"/></a>

---

### 2. **Accessing Wazuh Platform and Monitoring Security Events**

#### **Step 3: Log into Wazuh Web Interface**
Next, I accessed the Wazuh interface from **Kali Linux** via the browser at `10.1.16.242` and logged in as `admin`.

<img src="https://github.com/Hashdan-M/Incident-Response-Detection-with-Wazuh/blob/2c7f121347df99bd6fc47a5fe53f3f71089dbd77/Incident%20Response/3.PNG" width=50% height=50%>

#### **Step 4: View Security Events for DC10**
Once logged into Wazuh, I navigated to the **Security Events** tab

<img src="https://github.com/Hashdan-M/Incident-Response-Detection-with-Wazuh/blob/2c7f121347df99bd6fc47a5fe53f3f71089dbd77/Incident%20Response/4.PNG"/></a>

I filtered the alerts to display only the events from **DC10** (Windows Server 2019). To narrow down the events to only those related to DC10, I selected **Explore agent** and chose **DC10** from the dropdown.

<img src="https://github.com/Hashdan-M/Incident-Response-Detection-with-Wazuh/blob/2c7f121347df99bd6fc47a5fe53f3f71089dbd77/Incident%20Response/5.png"/></a>

---

### 3. **Simulating Attacks Using Hydra**

#### **Step 5: Perform Dictionary-based Brute-Force Attack Using Hydra**
I used the **Hydra** tool to simulate a password-guessing attack against the **RDP (Remote Desktop Protocol)** service on **DC10**, targeting the `administrator` account. The attack utilized the `passlist.txt` file created earlier, and the goal was to guess the password through a dictionary-based attack.

```bash
hydra -t 1 -V -f -l administrator -P passlist.txt rdp://10.1.16.1
```

- **Explanation of Parameters**:
  - `-t 1`: One task at a time (i.e., single-threaded).
  - `-V`: Verbose mode to show each attempt.
  - `-f`: Stop the attack once the correct password is found.

The output showed 57 attempts, with the 57th attempt successfully guessing the password.

#### **Step 6: View the Wazuh Alert for Password Guessing**
After running the Hydra attack, I returned to the Wazuh web interface and refreshed the security events page. I searched for **Rule ID 92652**, which is associated with successful password discovery.

- This event showed up as a **High severity alert** related to the successful use of a weak password.

---

### 4. **Further Testing: Attempt to Mount Windows Share**

#### **Step 7: Mount Windows Administrative Share**
I attempted to mount a Windows administrative share (`C$`) using the **Jaime** and **Administrator** accounts.

```bash
mkdir /mnt/dc10-c
mount -o username=jaime //10.1.16.1/c$ /mnt/dc10-c   # Failed attempt
mount -o username=administrator //10.1.16.1/c$ /mnt/dc10-c  # Successful attempt
```

#### **Step 8: Monitor Security Alerts for Mount Attempts**
I returned to Wazuh, refreshed the security events, and searched for the rule IDs:
- **Rule ID 60122** for failed login attempts.
- **Rule ID 60106** for successful login attempts.

The alerts provided detailed information on each attempt, including the user, IP address, and method of access (e.g., RDP or file share).

---

### 5. **Simulating Anti-Forensics Activity: Log Deletion**

#### **Step 9: Clear Windows Security Logs**
To simulate anti-forensics activity, I cleared the **Windows Security log** using the **Event Viewer**.

- Open **Event Viewer**, navigate to **Windows Logs > Security**, and select **Clear Log**.

#### **Step 10: Detect Log File Deletion in Wazuh**
I returned to Wazuh and searched for **Rule ID 63103**, which is associated with the clearing of event logs. This is a typical anti-forensics technique used by attackers to erase traces of their malicious activity.

```text
Search for Rule ID: 63103
```

Wazuh detected this event and generated an alert indicating that a log file had been cleared, including the timestamp and affected system.

---

### 6. **Final Checks and Analysis**

#### **Step 11: Review Security Alerts**
I reviewed the various security alerts generated by Wazuh for the following activities:
- **Password guessing attempts** (Rule ID 92652).
- **Failed and successful logon attempts** (Rule ID 60122 for failures and Rule ID 60106 for successes).
- **Clearing of event logs** (Rule ID 63103).

#### **Step 12: Evaluate the MITRE ATT&CK Techniques**
For each event, I reviewed the **MITRE ATT&CK** technique that was associated with the detected activity. For instance, **T1078** (Valid Accounts) was identified in some of the logon attempts, and **T1071** (Application Layer Protocol) was related to the password-guessing activity.

---

## Key Takeaways

1. **Wazuh Detection**: Wazuh effectively detected multiple suspicious activities, including brute-force password guessing and log file deletions.
2. **Automated Alerting**: Automated alerts provided real-time visibility into security incidents and enabled a faster response.
3. **Incident Response**: This project demonstrates the importance of automated detection and monitoring in an incident response workflow. By identifying malicious activities such as password guessing and anti-forensic techniques like log deletion, security teams can react more quickly to mitigate potential risks.

---

## Screenshots

- **Wazuh Dashboard**: Screenshot of the Wazuh dashboard after login.
- **Security Events**: Screenshots of Wazuh alerts related to password guessing and logon failures.
- **Hydra Attack**: Screenshot of the Hydra tool running and successfully guessing the password.
- **Log Deletion Detection**: Screenshot showing Wazuh alert for log file deletion.

---

This project not only demonstrates how to configure Wazuh to detect suspicious activities but also highlights the real-world relevance of tools like Hydra and Wazuh for threat detection and incident response.

### Additional Resources
- [Wazuh Official Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

### Conclusion
By combining penetration testing with real-time monitoring using Wazuh, I was able to simulate, detect, and respond to various types of attacks and anti-forensic activity. This experience has provided valuable insights into security operations and incident response capabilities.

---

Feel free to attach screenshots of each step, particularly those showing the W

azuh web interface, alert logs, and the output from Hydra, to give your project a clear visual structure.
