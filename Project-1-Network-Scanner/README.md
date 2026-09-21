# Python Network Port Scanner

A beginner cybersecurity project built with Python to understand network ports, TCP connections, basic service detection, and security exposure.

## Overview

This project is a Python-based network port scanner that checks ports **1–10,000** on a target IP address.

For ports that are open, the scanner attempts basic service identification and provides a simple security observation.

The scanner also uses multithreading to improve scanning speed.

## Features

* Scans ports 1–10,000
* Detects open TCP ports
* Uses concurrent scanning with `ThreadPoolExecutor`
* Performs basic service detection
* Detects HTTP and MySQL responses
* Displays detected service/version information
* Provides basic security observations
* Generates a `scan_report.txt` file
* Measures total scan time

## Technologies Used

* Python 3
* Socket programming
* TCP/IP
* `ThreadPoolExecutor`
* Git & GitHub

## How It Works

The scanner follows these basic steps:

1. Takes a target IP address from the user.
2. Attempts a TCP connection to ports 1–10,000.
3. Identifies ports where the connection succeeds.
4. Sends basic requests/data to open ports to identify supported services.
5. Provides a security observation based on the detected service.
6. Displays the results in the terminal.
7. Saves the results to `scan_report.txt`.

## Example Results

Example scan of a local machine:

```text
PORT    STATE     SERVICE     VERSION
------------------------------------------------------------
135     OPEN      Unknown     -
445     OPEN      Unknown     -
3306    OPEN      MySQL       9.7.1
5040    OPEN      Unknown     -
8000    OPEN      HTTP        SimpleHTTP/0.6 Python/3.13.7
```

## Limitations

This project is intended for learning and basic network reconnaissance.

It does **not** perform:

* Vulnerability scanning
* Exploitation
* Password attacks
* Full service fingerprinting
* Comprehensive security assessment

An open port does not automatically mean that a vulnerability exists. Further investigation would be required.

## What I Learned

Through this project, I learned:

* How TCP sockets work in Python
* How port scanning works
* How `connect_ex()` can be used to test connectivity
* How concurrent execution can improve scanning speed
* How basic service detection can be performed using server responses
* How exposed services can represent potential areas for security review
* How to use Git and GitHub to manage a cybersecurity project

## Disclaimer

This tool is intended for **educational purposes and authorized testing only**.

Only scan systems and networks that you own or have explicit permission to test.
