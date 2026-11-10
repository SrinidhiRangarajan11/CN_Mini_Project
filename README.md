# Authentication-Based SDN Access Control

## 1. Project Overview

This project implements an authentication-based network access control system using Software-Defined Networking (SDN).

The system integrates a TCP authentication server with an OS-Ken SDN controller and an Open vSwitch (OVS) switch managed through Mininet.

Clients must successfully authenticate before accessing a protected TCP service. The SDN controller dynamically installs OpenFlow rules when authentication succeeds and removes them when a client logs out or disconnects.

## 2. Project Objectives

- Implement username/password authentication through a TCP server.
- Integrate authentication with an SDN controller.
- Enforce network access policies using OpenFlow 1.3.
- Block unauthenticated clients from accessing protected services.
- Dynamically grant and revoke network access.
- Maintain authentication and access logs.
- Prevent unauthorised clients from directly requesting policy changes through the REST API.

## 3. System Architecture

The project consists of five main components:

1. **Client:** Initiates authentication and requests access to the protected service.
2. **Authentication Server:** Validates credentials and notifies the SDN controller.
3. **OS-Ken SDN Controller:** Manages access policies and communicates with the OpenFlow switch.
4. **Open vSwitch:** Enforces forwarding and access-control rules.
5. **Protected Service:** Provides TCP service access to authorised clients.

### Architecture Diagram

```text
                 +----------------------+
                 |      Client h1       |
                 |      10.0.0.1        |
                 +----------+-----------+
                            |
                            | TCP / 9000
                            v
                 +----------------------+
                 | Authentication       |
                 | Server: h_auth       |
                 | 10.0.0.2             |
                 +----------+-----------+
                            |
                            | HTTP POST
                            | /auth/policy
                            v
                 +----------------------+
                 | OS-Ken SDN           |
                 | Controller           |
                 +----------+-----------+
                            |
                            | OpenFlow 1.3
                            | Port 6653
                            v
                 +----------------------+
                 | Open vSwitch: s1     |
                 | Access Control       |
                 +----------+-----------+
                            |
                            | TCP / 8080
                            v
                 +----------------------+
                 | Protected Service    |
                 | h_service            |
                 | 10.0.0.3             |
                 +----------------------+
```

## 4. Network Configuration

| Component | Host | IP Address | Port |
|---|---|---|---|
| Primary Client | h1 | 10.0.0.1 | Dynamic |
| Secondary Client | h2 | 10.0.0.12 | Dynamic |
| Third Client | h3 | 10.0.0.13 | Dynamic |
| Authentication Server | h_auth | 10.0.0.2 | 9000 |
| Protected Service | h_service | 10.0.0.3 | 8080 |
| Controller REST API | s1 management IP | 10.0.0.254 | 8081 |
| OpenFlow Controller | Controller | 127.0.0.1 | 6653 |

## 5. OpenFlow Access-Control Mechanism

The SDN controller implements access control using OpenFlow flow entries.

### Flow Priorities

| Priority | Purpose | Action |
|---|---|---|
| 400 | Authenticated client access | Allow |
| 300 | Default protected-service policy | Drop |
| 1 | MAC forwarding | Forward |
| 0 | Table-miss rule | Send to controller |

### Default Blocking

When the switch connects, the controller installs a priority-300 rule matching TCP traffic destined for:

- Destination IP: 10.0.0.3
- Destination port: 8080

Matching packets are dropped.

### Dynamic GRANT

After successful authentication, the authentication server sends a GRANT request to the controller.

The controller installs two priority-400 rules:

- Client to protected service.
- Protected service to client.

These rules take precedence over the default priority-300 DROP rule.

### Dynamic REVOKE

When a client logs out or disconnects, the authentication server sends a REVOKE request.

The controller removes the client's flow entries using a client-specific OpenFlow cookie.

The default DROP rule remains active.

## 6. Authentication Workflow

1. The client establishes a TCP connection to the authentication server.
2. The client submits a username and password.
3. The authentication server validates the credentials.
4. Invalid credentials are rejected without granting network access.
5. Valid credentials result in a session token being generated.
6. The authentication server sends a GRANT request to the SDN controller.
7. The controller installs the appropriate OpenFlow rules.
8. The client can access the protected TCP service.
9. On logout or unexpected disconnection, the authentication server attempts to send a REVOKE request.
10. The controller removes the client's access rules.

## 7. Project Structure

```text
CN_Mini_Project/
|
|-- app/
|   |-- auth_server.py
|   |-- client.py
|   |-- protected_server.py
|
|-- controller/
|   |-- __init__.py
|   |-- access_logger.py
|   |-- config.py
|   |-- flow_manager.py
|   |-- rest_api.py
|   |-- sdn_controller.py
|
|-- topology/
|   |-- topo.py
|
|-- results/
|   |-- auth.log
|
|-- logs/
|   |-- access.log
|
|-- auth_server.py
|-- client.py
|-- protected_server.py
|-- .gitignore
|-- README.md
```

The root-level server and client files contain the integrated Mininet implementation. The `app/` directory retains the original application files.

## 8. Requirements

The project requires:

- Ubuntu Linux
- Python 3
- Mininet
- Open vSwitch
- OS-Ken SDN Controller
- Python Requests library
- OpenFlow 1.3 support

## 9. Execution Instructions

Open three Ubuntu terminals.

### Terminal 1: Start the SDN Controller

Navigate to the project directory:

```bash
cd ~/projects/CN_Mini_Project
```

Start OS-Ken:

```bash
PYTHONPATH="$PWD" osken-manager controller/sdn_controller.py
```

Keep this terminal running.

### Terminal 2: Start Mininet

Navigate to the project directory:

```bash
cd ~/projects/CN_Mini_Project
```

Start the custom topology:

```bash
sudo mn --custom topology/topo.py --topo access --controller=remote,ip=127.0.0.1,port=6653 --switch ovsk,protocols=OpenFlow13 --mac
```

Once the Mininet CLI appears, configure the switch management IP:

```bash
sh ip link set s1 up
sh ip addr add 10.0.0.254/24 dev s1
```

Start the protected server:

```bash
h_service python3 -u /home/smayan/projects/CN_Mini_Project/protected_server.py &
```

Start the authentication server:

```bash
h_auth python3 -u /home/smayan/projects/CN_Mini_Project/auth_server.py &
```

Keep Mininet running.

### Terminal 3: Run the Client

From the Mininet CLI in Terminal 2:

```bash
h1 python3 -u /home/smayan/projects/CN_Mini_Project/client.py
```

Enter the credentials when prompted.

### Demonstration Credentials

| Username | Password |
|---|---|
| alice | password123 |
| bob | secure456 |
| charlie | tcp789 |

These are demonstration credentials defined in the authentication server.

## 10. Testing and Verification

The following functional and security tests were executed successfully.

| Test Case | Expected Result | Result |
|---|---|---|
| Unauthenticated h1 access | Connection blocked | Passed |
| Valid Alice login | Authentication successful | Passed |
| Successful login triggers GRANT | Priority-400 rules installed | Passed |
| Authenticated client accesses protected service | Access granted | Passed |
| Explicit logout | REVOKE triggered | Passed |
| Access after logout | Connection blocked | Passed |
| Unexpected client disconnect | Automatic REVOKE attempted | Passed |
| Access after unexpected disconnect | Connection blocked | Passed |
| Invalid password | Authentication rejected | Passed |
| Unauthenticated h2 access | Connection blocked | Passed |
| Direct REST GRANT request from h2 | HTTP 403 Forbidden | Passed |

### Checking OpenFlow Rules

Use the following command inside Mininet:

```bash
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Expected observations:

- A priority-300 DROP rule for the protected service.
- Priority-400 rules for an authenticated client.
- Priority-400 rules removed following successful revocation.

### Testing Unauthorised Access

From the Mininet CLI:

```bash
h2 nc -vz -w 3 10.0.0.3 8080
```

The connection should time out because h2 has not been authorised.

## 11. Logging

The project maintains two categories of logs.

### Authentication Logs

Location:

```text
results/auth.log
```

Records successful logins, failed login attempts, logouts and controller communication errors.

### SDN Access Logs

Location:

```text
logs/access.log
```

Records switch connection events, GRANT operations, REVOKE operations and security events.

Generated logs and Python cache files are excluded from Git tracking.

## 12. Security Considerations and Limitations

This implementation is intended as an academic SDN demonstration.

Current limitations include:

- Credentials are stored in plaintext in the demonstration credential store.
- The system uses client IP addresses for network-level access policies.
- Session tokens are generated securely but are not independently validated by the protected service.
- The REST API uses source-IP restrictions rather than cryptographic API authentication.
- Session expiry and brute-force account lockout are not currently implemented.
- If controller communication fails during revocation, access rules may remain installed and require further intervention.

Production deployment would require stronger credential storage, authenticated and encrypted controller API communication, session expiry, rate limiting and improved failure recovery.

## 13. Conclusion

The project demonstrates how Software-Defined Networking can integrate with a TCP authentication system to provide dynamic network access control.

By combining an authentication server, an OS-Ken SDN controller, OpenFlow 1.3 and Open vSwitch, the implementation allows authenticated clients to access protected resources while blocking unauthorised clients.

The system also demonstrates automatic access revocation following logout and unexpected client disconnection, along with REST API source restrictions and event logging.

The successful test results validate the core authentication-driven SDN access-control workflow.
