import ctypes
import sys
import sysv_ipc
import os
import shutil

SHM_ENV_VAR = "__AFL_SHM_ID"
MAP_SIZE_POW2 = 16
MAP_SIZE = (1 << MAP_SIZE_POW2)

def setup_shm(libc):
    shmget = libc.shmget
    shmat = libc.shmat
    shmat.restype = ctypes.c_void_p
    shmat.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
    shmid = shmget(sysv_ipc.IPC_PRIVATE, MAP_SIZE, sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL | 0o600)
    if shmid < 0:
        sys.exit("cannot get shared memory segment with key %d" % (sysv_ipc.IPC_PRIVATE))
    shmptr = shmat(shmid, None, 0)
    if shmptr == 0 or shmptr == -1:
        sys.exit("cannot attach shared memory segment with id %d" % (shmid))
    print(f'created shared memory, shmid: {shmid}')
    return shmid, shmptr

def clear_shm(trace_bits):
    ctypes.memset(trace_bits, 0, MAP_SIZE)

def check_crash(status_code):
    crashed = False
    if status_code in [6, 134]:  # Abort
        crashed = True
        print("Found an abort!")
    elif status_code == 8:  # Floating-point error
        crashed = True
        print("Found a float-point error!")
    elif status_code in [11, 139]:  # Segfault
        crashed = True
        print("Found a segfault!")
    elif status_code != 0:  # Any non-zero exit
        crashed = True
        print(f"Found a potential crash with status code {status_code}!")
    return crashed

def check_coverage(trace_bits):
    raw_bitmap = ctypes.string_at(trace_bits, MAP_SIZE)
    return Feedback().analyze_coverage(raw_bitmap)

class Feedback:
    def __init__(self):
        self.global_coverage = set()

    def analyze_coverage(self, raw_bitmap):
        new_edge_covered = False
        total_hits = 0
        for i, byte in enumerate(raw_bitmap):
            if byte != 0:
                total_hits += 1
                if i not in self.global_coverage:
                    self.global_coverage.add(i)
                    new_edge_covered = True
        print(f'covered {len(self.global_coverage)} edges')
        return new_edge_covered, total_hits

    def save_seed(self, seed, conf):
        seed_path = os.path.join(conf['queue_folder'], f"seed_{seed.seed_id}")
        shutil.copy(seed.path, seed_path) 