import os
import sys

os.environ["SENTINEL_FORCE_OFFLINE"] = "1"  # tests never hit the network
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
