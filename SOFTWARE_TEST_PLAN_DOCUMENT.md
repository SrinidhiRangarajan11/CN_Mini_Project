# Software Test Plan (STP)

**Project Title: Dynamic TCP Authentication and Access Control using Software-Defined Networking (SDN)**

## **1\. Introduction**

## 1.1 Purpose

The purpose of this Software Test Plan (STP) is to define the testing strategy, test environment, test cases, and pass/fail criteria for the **TCP Authentication SDN** project. This document ensures that the custom OS-Ken SDN controller, dynamic OpenFlow flow management, REST API interface, authentication server, and protected service operate together securely and reliably.

### 1.2 Scope

This test plan covers end-to-end functional, security, and network-layer verification of the system, including:

* Default-deny network security posture on the OpenFlow switch (s1).  
* Address Resolution Protocol (ARP) handling and Layer 2 connectivity.  
* Unauthenticated access to the TCP Authentication Server (10.0.0.2:9000).  
* Credential validation and REST API communication between the Auth Server and SDN Controller (127.0.0.1:8081).  
* Dynamic OpenFlow rule installation (GRANT action) and subsequent access to the Protected Service (10.0.0.3:8080).

### 

### 1.3 System Architecture Overview

* **Client Hosts (h1, h2, h3):** End-user nodes requesting access to protected network resources (10.0.0.1, etc.).  
* **Authentication Server (h\_auth):** Listens on 10.0.0.2:9000 over TCP, verifies user credentials, and notifies the SDN controller via HTTP REST.  
* **Protected Service (h\_service):** Restricted application server listening on 10.0.0.3:8080.  
* **SDN Switch (s1):** Open vSwitch (OVS) instance operating under OpenFlow 1.3.  
* **SDN Controller (c0):** Custom os-ken controller listening on OpenFlow port 6633 and exposing a WSGI REST API on port 8081\.

## **2\. Test Environment & Prerequisites**

### 2.1 Hardware & Software Requirements

* **Operating System:** Ubuntu Linux (22.04 LTS or later)  
* **Network Emulator:** Mininet (v2.3.0+) with Open vSwitch  
* **SDN Framework:** OS-Ken (os\_ken) Python library (OpenFlow v1.3)  
* **Runtime:** Python 3.10+

### 2.2 Environment Initialization

1. **Controller Startup:** Launch the SDN controller via python3 \-m os\_ken.cmd.manager controller.sdn\_controller.  
2. **Topology Initialization:** Launch Mininet via sudo mn \--custom topology/topo.py \--topo access \--controller remote,ip=127.0.0.1,port=6633.  
3. **Service Deployment:** Start auth\_server.py on h\_auth and protected\_server.py on h\_service.

## 

## **3\. Test Strategy**

Testing will follow a bottom-up integration approach:

1. **Control & Data Plane Initialization:** Verify switch-to-controller handshake and proactive base flow installation.  
2. **Negative Security Testing:** Confirm unauthorized hosts are blocked from reaching protected services.  
3. **Authentication & API Integration Testing:** Verify TCP login and REST API GRANT trigger.  
4. **Positive Access Testing:** Verify post-authentication traffic reaches the protected service.  
5. **Isolation & Multi-Host Testing:** Confirm granting access to one host (h1) does not inadvertently expose the service to other unauthenticated hosts (h2).

## **4\. Detailed Test Cases**

### TC-01: Controller and Switch Handshake Verification

* **Objective:** Verify that switch s1 connects to the OS-Ken controller and installs baseline OpenFlow rules.  
* **Preconditions:** Controller is running on port 6633; Mininet topology is launched.  
* **Test Steps:**  
  1. Inspect the controller terminal logs upon Mininet startup.  
  2. Run sh ovs-ofctl \-O OpenFlow13 dump-flows s1 in the Mininet CLI.  
* **Expected Result:**  
  * Controller logs confirm switch connection (EventOFPSwitchFeatures).  
  * Flow table displays three proactive rules: Priority 0 (table-miss), Priority 20 (ARP flood), and Priority 15 (traffic to/from 10.0.0.2).

### 

### TC-02: ARP Resolution and Auth Server Reachability

* **Objective:** Verify that unauthenticated hosts can resolve MAC addresses and reach the Auth Server.  
* **Preconditions:** Baseline flows are installed on s1; auth\_server.py is running on h\_auth.  
* **Test Steps:**  
  1. Execute h1 ping \-c 2 10.0.0.2 in the Mininet CLI.  
* **Expected Result:** 2 packets transmitted, 2 received, 0% packet loss. ARP resolution succeeds without No route to host errors.

### TC-03: Negative Test – Unauthenticated Access Block

* **Objective:** Verify that an unauthenticated client cannot connect to the Protected Service (10.0.0.3:8080).  
* **Preconditions:** protected\_server.py is running on h\_service; h1 has not authenticated.  
* **Test Steps:**  
  1. Execute h1 python3 \-c "import socket; s \= socket.socket(); s.settimeout(3); s.connect(('10.0.0.3', 8080))" in the Mininet CLI.  
* **Expected Result:** Connection fails with TimeoutError: timed out. Switch s1 drops the TCP SYN packets due to the default-deny table-miss rule.

### TC-04: Invalid Credential Rejection

* **Objective:** Verify that failed login attempts do not trigger OpenFlow rule installation.  
* **Preconditions:** auth\_server.py is active on 10.0.0.2:9000.  
* **Test Steps:**  
  1. Execute h1 python3 app/client.py.  
  2. Enter valid username alice and invalid password wrongpass.  
* **Expected Result:**  
  * Auth Server returns an authentication failure message.  
  * No POST request is sent to the controller REST API (127.0.0.1:8081).  
  * h1 remains blocked from 10.0.0.3:8080.

### TC-05: Positive Test – Successful Authentication & Dynamic Flow Grant

* **Objective:** Verify end-to-end authentication, REST API flow provisioning, and access to the Protected Service.  
* **Preconditions:** auth\_server.py and protected\_server.py are running; h1 is unauthenticated.  
* **Test Steps:**  
  1. Execute h1 python3 app/client.py.  
  2. Enter username alice and password password123.  
  3. Enter y when prompted to test connecting to the Protected Service.  
* **Expected Result:**  
  * Auth Server validates credentials and sends POST /access with {"ip": "10.0.0.1", "action": "GRANT"} to port 8081\.  
  * Controller installs high-priority bidirectional OpenFlow rules permitting traffic between 10.0.0.1 and 10.0.0.3.  
  * Client h1 connects to 10.0.0.3:8080 and prints the Protected Service welcome banner.

### TC-06: Host Isolation Verification

* **Objective:** Ensure dynamic authorization is strictly scoped to the authenticated client IP (10.0.0.1) and does not grant network-wide access.  
* **Preconditions:** h1 has completed TC-05 and has active access to 10.0.0.3.  
* **Test Steps:**  
  1. From unauthenticated host h2 (10.0.0.4 or assigned IP), execute: h2 python3 \-c "import socket; s \= socket.socket(); s.settimeout(3); s.connect(('10.0.0.3', 8080))"  
* **Expected Result:** Connection from h2 times out (TimeoutError), proving flow rules are strictly matched on ipv4\_src / ipv4\_dst for h1.

## 

## **5\. Pass/Fail & Exit Criteria**

### 5.1 Pass Criteria

A test case is marked **PASS** only when the actual output matches the expected result without unhandled exceptions, packet leaks, or controller crashes.

### 5.2 Project Exit Criteria

The project is considered verified and ready for demonstration when:

* **100%** of Critical Security Test Cases (**TC-01**, **TC-03**, **TC-04**, **TC-06**) pass.  
* **100%** of Functional End-to-End Test Cases (**TC-02**, **TC-05**) pass.  
* Clean teardown (sudo mn \-c) completes without orphaned OVS bridges or zombie processes.

##   **6\. Test Execution Summary Log** 

| Test ID | Test Case Description | Status (Pass/Fail) |
| :---- | :---- | :---- |
| **TC-01** | Controller & Switch Handshake | Pass |
| **TC-02** | ARP & Auth Server Reachability | Pass |
| **TC-03** | Unauthenticated Access Block | Pass |
| **TC-04** | Invalid Credential Rejection | Pass |
| **TC-05** | End-to-End Auth & Flow Grant | Pass |
| **TC-06** | Multi-Host Isolation Check | Pass |

