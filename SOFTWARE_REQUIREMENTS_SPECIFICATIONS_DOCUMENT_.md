# **Software Requirements Specification (SRS)**

**Project Title: Dynamic TCP Authentication and Access Control using Software-Defined Networking (SDN)**

## 

## **Table of Contents**

| Introduction |
| :---- |
| **Overall Description** |
| **External Interface Requirements** |
| **System Features** |
| **Other Nonfunctional Requirements** |
| **Appendix A: Glossary** |
| **Appendix B: Analysis Models** |

## 

## 

## **1\. Introduction**

### **1.1 Purpose**

This document specifies the software requirements for the **TCP Authentication and Network Access Control System using Software-Defined Networking (SDN)**. The system enforces dynamic network access control by restricting default data plane access until a host successfully authenticates against a centralized TCP Authentication Server.

### 

### **1.2 Document Conventions**

* Requirements are uniquely identified using prefixes: FR for Functional Requirements and NFR for Non-Functional Requirements.  
* The term **"SHALL"** indicates a mandatory requirement.


### **1.3 Intended Audience and Reading Suggestions**

This SRS is intended for project evaluators, software developers (Member 1), controller developers (Member 2), and network/testing engineers (Member 3).

### **1.4 Product Scope**

The system addresses unauthorized network traversal in enterprise environments. By isolating unauthenticated hosts at the switch level via OpenFlow rules, it prevents unauthorized access to protected services until valid credentials are provided.

### **1.5 References**

1. IEEE Std 830-1998: *IEEE Recommended Practice for Software Requirements Specifications*.  
2. OpenFlow Switch Specification Version 1.3.0.  
3. Mininet & OSken SDN Controller Documentation.

## 

## **2\. Overall Description**

### **2.1 Product Perspective**

The system operates within an Ubuntu Linux environment inside a Mininet-emulated network topology managed by Open vSwitch (OVS) and an SDN Controller.

### 

### 

### 

### 

### **2.2 Product Functions**

* **Default Isolation:** Blocks all raw TCP traffic destined for the Protected Service (Port 8080\) by default.  
* **Credential Verification:** Authenticates users via socket connection on Port 9000\.  
* **Dynamic Policy Enforcement:** Instructs the SDN controller to push flow rules allowing Port 8080 access upon successful login.  
* **Session Revocation:** Removes flow rules upon logout, timeout, or failed access attempts.  
* **Audit Logging:** Logs authentication events locally in results/auth.log.

### 

### **2.3 User Classes and Characteristics**

* **Unauthenticated Client:** Restricted host permitted only to send authentication queries to h\_auth.  
* **Authenticated Client:** Validated host granted temporary access to h\_service.  
* **System Administrator:** Reads results/auth.log and configures user credentials/timeouts.  
* 

### **2.4 Operating Environment**

* **Operating System:** Ubuntu 22.04 LTS / Virtual Machine.  
* **Environment:** Python 3 (standard libraries: socket, threading, logging, requests).  
* **SDN Stack:** Mininet, Open vSwitch (OVS), Ryu or POX Controller (OpenFlow 1.3).  
* 

### **2.5 Design and Implementation Constraints**

* Core protocol implementation must use raw socket programming (no high-level web frameworks).  
* Policy enforcement must occur dynamically on the data plane using OpenFlow rules.  
* 

### **2.6 Assumptions and Dependencies**

* Mininet correctly instantiates virtual switches and host interfaces.  
* The SDN controller REST API is reachable by the TCP Auth Server.

## 

## 

## 

## 

## 

## 

## 

## **3\. External Interface Requirements**

### **3.1 User Interfaces**

* Command-line interface (CLI) driven by app/client.py for entering credentials and issuing requests.


### **3.2 Hardware Interfaces**

* Standard x86\_64 / ARM virtualized network interfaces configured inside Mininet.


### **3.3 Software Interfaces**

* **TCP Auth Server (app/auth\_server.py):** Listens on Port 9000\.  
* **Protected Service (app/protected\_server.py):** Listens on Port 8080\.  
* **SDN Controller REST API:** Exposed on Port 8080/8081 for HTTP POST notifications.  
* 

### **3.4 Communications Interfaces**

* TCP/IP protocol stack for application sockets.  
* OpenFlow 1.3 protocol for controller-to-switch communication.  
* HTTP/REST JSON payloads ({"ip": client\_ip, "action": "GRANT\|REVOKE"}) for server-to-controller communication.

## 

## 

## 

## 

## 

## 

## 

## **4\. System Features**

### **4.1 Feature 1: Default Network Access Control**

* **Description:** Restricts default data plane forwarding.  
* **FR-1.1:** The SDN controller SHALL install a high-priority default drop/deny rule for all traffic targeting the Protected Service IP and Port 8080 upon startup.  
* **FR-1.2:** The controller SHALL permit initial TCP traffic directed to the Auth Server IP on Port 9000\.

### **4.2 Feature 2: TCP Authentication & Session Token Management**

* **Description:** Verifies client identity and manages session lifecycle.  
* **FR-2.1:** The Auth Server SHALL listen for concurrent client socket connections on Port 9000\.  
* **FR-2.2:** The Auth Server SHALL validate credentials against USER\_CREDENTIALS and return AUTH\_OK TOKEN:\<token\> or AUTH\_FAIL.  
* **FR-2.3:** Upon successful verification, the Auth Server SHALL issue a GRANT REST trigger to the SDN Controller.


### **4.3 Feature 3: Dynamic OpenFlow Flow Rule Modification**

* **Description:** Updates data plane forwarding rules in real time.  
* **FR-3.1:** Upon receiving a GRANT trigger for a given IP, the SDN controller SHALL push an OpenFlow rule (Priority \> Default Drop) permitting traffic from client\_ip to protected\_server\_ip:8080.  
* **FR-3.2:** Upon receiving a REVOKE trigger (or session logout), the controller SHALL delete the corresponding flow rule.

### 

### 

### **4.4 Feature 4: Audit and Security Event Logging**

* **Description:** Tracks security events for auditing.  
* **FR-4.1:** The Auth Server SHALL append all SUCCESSFUL\_LOGIN, FAILED\_LOGIN, and LOGOUT events with ISO timestamps and client IP addresses to results/auth.log.

## 

## 

## **5\. Other Nonfunctional Requirements**

### **5.1 Performance Requirements**

* **NFR-1 (Latency):** Authentication processing and REST notification overhead SHALL take less than 100ms.  
* **NFR-2 (Flow Rule Install Time):** The SDN controller SHALL install the dynamic flow rule within 50ms of receiving the REST trigger.


### **5.2 Security Requirements**

* **NFR-3 (Isolation):** Unauthenticated hosts SHALL NOT be able to establish a TCP handshake with the Protected Service on Port 8080\.  
* **NFR-4 (Brute-Force Resistance):** Repeated failed login attempts SHALL be logged and trigger an automatic lockout/REVOKE signal.

### **5.3 Software Quality Attributes**

* **Reproducibility:** The repository SHALL build, execute, and verify cleanly from a fresh clone using only README.md instructions.  
* **Maintainability:** Code SHALL adhere to modular directory standards (app/, controller/, topology/, results/, docs/).

## 

## 

## **Appendix A: Glossary**

* **Mininet:** A network emulator for creating virtual hosts, switches, and links.  
* **OpenFlow:** The communications protocol that gives an SDN controller direct access to the forwarding plane of network switches.  
* **OVS (Open vSwitch):** A production-quality, multilayer virtual switch.  
* **REST API:** Representational State Transfer HTTP interface used for server-controller IPC.

## 

## **Appendix B: Analysis Models**

### **Sequence Diagram: Authentication & Dynamic Enforcement**