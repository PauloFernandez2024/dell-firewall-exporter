import os
import subprocess
import time

'''
Power draw per CPU core (W)     intel_rapl (calculado ou exporter)
CPU frequency per core (Hz)     node_cpu_scaling_frequency_hertz
Governor mode per core  node_cpu_scaling_governor
Total system power (W)  ipmi_sensor_value ou ipmi_power_watts
'''

def read_file(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except:
        return None


def get_cpu_scaling_info():
    cpu_data = {}
    cpu_path = "/sys/devices/system/cpu/"
    for cpu in sorted([d for d in os.listdir(cpu_path) if d.startswith("cpu") and d[3:].isdigit()]):
        idx = cpu[3:]
        base = os.path.join(cpu_path, cpu, "cpufreq")
        if os.path.exists(base):
            cur = read_file(os.path.join(base, "scaling_cur_freq"))
            minf = read_file(os.path.join(base, "scaling_min_freq"))
            maxf = read_file(os.path.join(base, "scaling_max_freq"))
            gov = read_file(os.path.join(base, "scaling_governor"))
            cpu_data[idx] = {
                "cur_freq_khz": cur if cur else "0",
                "min_freq_khz": minf if minf else "0",
                "max_freq_khz": maxf if maxf else "0",
                "governor": gov if gov else "unknown"
            }
    return cpu_data


def get_rapl_power():
    base_path = "/sys/class/powercap/intel-rapl:0/"
    if os.path.exists(base_path):
        energy_path = os.path.join(base_path, "energy_uj")
        time_interval = 1  # seconds
        e1 = read_file(energy_path)
        time.sleep(time_interval)
        e2 = read_file(energy_path)
        if e1 is None or e2 is None:
            return None
        e1 = int(e1)
        e2 = int(e2)
        delta_joules = (e2 - e1) / 1_000_000.0  # convert µJ to J
        power_watts = delta_joules / time_interval
        return { 'rapl_cpu_power_watts': str(round(power_watts, 2)) }
    return None


def get_ipmi():
    stats = {}
    try:
        response = subprocess.check_output(['ipmitool', 'sdr'], text=True)
    except subprocess.CalledProcessError as e:
        return stats
    temperature = re.compile(r'([\d\.]+)\s+degrees\s+C', re.IGNORECASE)
    fan = re.compile(r'([\d\.]+)\s+RPM', re.IGNORECASE)
    energy = re.compile(r'([\d\.]+)\s+Watts', re.IGNORECASE)
    for line in response.strip().split('\n'):
        parts = line.split('|')
        if len(parts) < 2:
            continue
        part = parts[1].strip()
        match_temp = temperature.search(part)
        if match_temp:
            try:
                value = float(match_temp.group(1))
                stats["ipmi_temperature_celsius"] = value
            except ValueError:
                pass
            continue
        match_fan = fan.search(part)
        if match_fan:
            try:
                value = float(match_fan.group(1))
                stats["ipmi_fan_speed_rpm"] = value
            except ValueError:
                pass
            continue
        match_energy = energy.search(part)
        if match_energy:
            try:
                value = float(match_energy.group(1))
                stats["ipmi_power_watts"] = value
            except ValueError:
                pass
            continue
    return stats
