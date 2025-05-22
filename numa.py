import os
import subprocess

'''
numa statistics
'''
def get_nodes():
    try:
        result = subprocess.run(["numastat"], capture_output=True, text=True)
        lines = result.stdout.strip().splitlines()
        headers = lines[0].split()
        stats = {}
        for line in lines[1:]:
            parts = line.split()
            metric = parts[0]
            values = list(map(int, parts[1:]))
            stats[metric] = dict(zip(headers, values))
        return stats
    except FileNotFoundError:
        return {}
    except subprocess.CalledProcessError:
        return {}

