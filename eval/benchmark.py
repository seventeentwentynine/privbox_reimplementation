"""
Performance/Big-O Evaluation

benchmark.py
"""
import requests
import time
import csv
import os

# Container endpoints (from `docker-compose.yml`)
RG_URL = "http://localhost:8001"
MB_URL = "http://localhost:8002"
SENDER_URL = "http://localhost:8003"
