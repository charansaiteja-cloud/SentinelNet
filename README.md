# SentinelNet 🛡️

A lightweight, Python-based Network Intrusion Detection System (NIDS) simulation tool.
<div align="center">

![CI/CD Pipeline](https://github.com/charansaiteja-cloud/SentinelNet/actions/workflows/ci.yml/badge.svg)
![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11-blue.svg)
![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)
![Type Checking: Mypy](https://img.shields.io/badge/mypy-strict-success.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

</div>

## 📐 Architecture Overview

```mermaid
graph TD
    A[Client / CLI Request] -->|Payload| B(Pydantic Validation Layer)
    B -->|Validated Target| C{Sentinel Async Engine}
    C -->|Concurrency Semaphore| D[Worker 1: Port/Target Scan]
    C -->|Concurrency Semaphore| E[Worker 2: Port/Target Scan]
    D & E --> F[(Structured Log Pipeline)]
    F --> G[JSON Output / Results]

## 🌟 Engineering Highlights & Pro Features

* **⚡ High-Performance Asynchronous Core:** Built on native Python `asyncio` and concurrency throttles to execute high-volume target operations smoothly Additional Profile Badges
Paste these alongside your existing badges at the top of your `README.md` to showcase code quality metrics:

```markdown
![Docker Ready](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)
![Security: Pydantic v2](https://img.shields.io/badge/pydantic-v2-E92063?logo=pydantic&logoColor=white)
![Maintained](https://img.shields.io/badge/maintained%3F-yes-brightgreen.svg)without blocking resources.
* **🔒 Enterprise Input Validation:** Leverages **Pydantic v2** models and strict type enforcement (`Mypy`) to ensure data integrity and prevent injection faults.
* **🐳 Production Containerization:** Features an optimized multi-stage `Dockerfile` and non-root user security configurations designed for minimal footprint and secure deployments.
* **🤖 Automated CI/CD Pipeline:** Fully integrated GitHub Actions workflows that automatically execute static analysis (`Ruff`), strict type-checking, and test suites (`Pytest`) on every pull request.
* **📊 Structured JSON Logging:** Replaced standard console prints with enterprise-ready structured loggers for clean tracking across production environments.

* 
## 🚀 Quick Start

1. **Clone the repository:**
   git clone [https://github.com/charansaiteja-cloud/SentinelNet.git](https://github.com/charansaiteja-cloud/SentinelNet.git)
   cd SentinelNet
cp .env.example .env
docker-compose up --build

================================================================================
SENTINELNET: INSTALLATION & USAGE

This document provides platform-specific instructions to set up, configure, and
run SentinelNet on Linux, macOS, and Windows.

PREREQUISITES

Python 3.10 or higher

Poetry (Dependency Management)

Docker & Docker Compose (Optional, for containerized execution)

LINUX & MACOS INSTALLATION & USAGE

Step 1: Clone the repository and enter the directory
git clone https://github.com/charansaiteja-cloud/SentinelNet.git
cd SentinelNet

Step 2: Set up environment variables
cp .env.example .env

Step 3: Install dependencies using Poetry
pip install poetry
poetry install

Step 4: Run the application
poetry run python -m sentinel_net.core

*Alternatively, run instantly via Docker:*
docker compose up --build


WINDOWS (POWERSHELL) INSTALLATION & USAGE

Step 1: Clone the repository and enter the directory via PowerShell
git clone https://github.com/charansaiteja-cloud/SentinelNet.git
cd SentinelNet

Step 2: Set up environment configuration
Copy-Item .env.example .env

Step 3: Install dependencies using Poetry
(Ensure Python and Poetry are installed and added to your system PATH)
pip install poetry
poetry install

Step 4: Run the application
poetry run python -m sentinel_net.core

*Alternatively, run via Docker Desktop:*
docker compose up --build


UNIVERSAL DOCKER DEPLOYMENT

If you have Docker Desktop (Windows/Mac) or Docker Engine (Linux) installed,
you can skip local environment setup entirely and run:

docker compose up --build


================================================================================
