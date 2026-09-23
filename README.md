# SentinelNet 🛡️

A lightweight, Python-based Network Intrusion Detection System (NIDS) and target inspection framework.

<div align="center">

![CI/CD Pipeline](https://github.com/charansaiteja-cloud/SentinelNet/actions/workflows/ci.yml/badge.svg)
![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11-blue.svg)
![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)
![Type Checking: Mypy](https://img.shields.io/badge/mypy-strict-success.svg)
![Docker Ready](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)
![Security: Pydantic v2](https://img.shields.io/badge/pydantic-v2-E92063?logo=pydantic&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

</div>

---

## 📐 Architecture Overview

```mermaid
graph TD
    A[Client / CLI Request] -->|Payload| B(Pydantic Validation Layer)
    B -->|Validated Target| C{Sentinel Async Engine}
    C -->|Concurrency Semaphore| D[Worker 1: Port/Target Scan]
    C -->|Concurrency Semaphore| E[Worker 2: Port/Target Scan]
    D & E --> F[(Structured Log Pipeline)]
    F --> G[JSON Output / Results]
🌟 Engineering Highlights & Pro Features
⚡ High-Performance Asynchronous Core: Built on native Python asyncio and concurrency throttles to execute high-volume target operations smoothly without blocking resources.

🔒 Enterprise Input Validation: Leverages Pydantic v2 models and strict type enforcement (Mypy) to ensure data integrity and prevent injection faults.

🐳 Production Containerization: Features an optimized multi-stage Dockerfile and non-root user security configurations designed for minimal footprint and secure deployments.

🤖 Automated CI/CD Pipeline: Fully integrated GitHub Actions workflows that automatically execute static analysis (Ruff), strict type-checking, and test suites (Pytest) on every pull request.

📊 Structured JSON Logging: Replaced standard console prints with enterprise-ready structured loggers for clean tracking across production environments.

💻 Installation & Usage Guide
This project supports cross-platform execution across Linux, macOS, and Windows.

Prerequisites
Python 3.10 or higher

Poetry (for Python dependency management)

Docker & Docker Compose (optional, for fully containerized execution)

🐧 For Linux & macOS
Clone the repository and enter the directory:

Bash
git clone [https://github.com/charansaiteja-cloud/SentinelNet.git](https://github.com/charansaiteja-cloud/SentinelNet.git)
cd SentinelNet
Set up your environment variables:

Bash
cp .env.example .env
Install dependencies using Poetry:

Bash
pip install poetry
poetry install
Run the application:

Bash
poetry run python -m sentinel_net.core
Alternatively, run instantly via Docker:

Bash
docker compose up --build
🪟 For Windows (PowerShell)
Clone the repository and enter the directory via PowerShell:

PowerShell
git clone [https://github.com/charansaiteja-cloud/SentinelNet.git](https://github.com/charansaiteja-cloud/SentinelNet.git)
cd SentinelNet
Set up your environment configuration:

PowerShell
Copy-Item .env.example .env
Install dependencies using Poetry:
(Make sure Python and Poetry are installed and available in your system PATH)

PowerShell
pip install poetry
poetry install
Run the application:

PowerShell
poetry run python -m sentinel_net.core
Alternatively, run via Docker Desktop:

PowerShell
docker compose up --build
🐳 Universal Docker Deployment
If you have Docker Desktop (Windows/macOS) or Docker Engine (Linux) installed, you can skip local environment setup entirely:

Bash
docker compose up --build
