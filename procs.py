import os


'''
fds per process
'''
def get_openfiles():
    processes = []

    for pid in filter(str.isdigit, os.listdir("/proc")):
        fd_path = f"/proc/{pid}/fd"
        comm_path = f"/proc/{pid}/comm"
        try:
            fd_count = len(os.listdir(fd_path))
            with open(comm_path) as f:
                cmd = f.read().strip()
            processes.append({
                "pid": str(pid),
                "open_fds": fd_count,
                "command": cmd
            })
        except (PermissionError, FileNotFoundError):
            continue  
    return {"processes": processes}

