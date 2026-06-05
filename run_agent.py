import sys
import os

# Ensure the parent directory is in sys.path so the package can be found
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from multiwan_qos_agent.app import main

if __name__ == "__main__":
    main()
