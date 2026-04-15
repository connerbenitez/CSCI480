from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import time
from datetime import datetime
import json
import os
from scapy.all import sniff, Ether, IP, TCP, UDP
from collections import defaultdict
import psutil
import pandas as pd
import sys
sys.path.append('..')
from ML.predict import load_models, predict_all  # relative import

app = Flask(__name__)
C
