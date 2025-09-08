import os
import argparse
import signal
import shutil
from conf import *
from libc import *
from feedback import *
from execution import *
from seed import *
from schedule import *
from mutation import *

FORKSRV_FD = 198

def signal_handler(sig, frame):
    print('You pressed Ctrl+C! Ending the fuzzing session...')
    sys.exit(0)

def run_forkserver(conf, ctl_read_fd, st_write_fd):
    os.dup2(ctl_read_fd, FORKSRV_FD)
    os.dup2(st_write_fd, FORKSRV_FD + 1)
    cmd = [conf['target']] + [arg.replace('@@', conf['current_input']) for arg in conf['target_args']]
    print(cmd)
    print(f'shmid is {os.environ[SHM_ENV_VAR]}')
    print(f'st_write_fd: {st_write_fd}')
    dev_null_fd = os.open(os.devnull, os.O_RDWR)
    os.dup2(dev_null_fd, 1)
    os.dup2(dev_null_fd, 2)
    os.execv(conf['target'], cmd)

def run_fuzzing(conf, st_read_fd, ctl_write_fd, trace_bits):
    read_bytes = os.read(st_read_fd, 4)
    if len(read_bytes) == 4:
        print("forkserver is up! starting fuzzing... press Ctrl+C to stop")

    crash_queue = []
    seed_queue = []
    feedback = Feedback()

    # Ensure queue and crash folders exist
    os.makedirs(conf['queue_folder'], exist_ok=True)
    os.makedirs(conf['crash_folder'], exist_ok=True)

    shutil.copytree(conf['seeds_folder'], conf['queue_folder'], dirs_exist_ok=True)
    for i, seed_file in enumerate(os.listdir(conf['queue_folder'])):
        seed_path = os.path.join(conf['queue_folder'], seed_file)
        if not os.path.exists(conf['current_input']):
            print(f"Warning: {conf['current_input']} does not exist, creating empty file")
            with open(conf['current_input'], 'wb') as f:
                f.write(b'')
        shutil.copyfile(seed_path, conf['current_input'])
        status_code, exec_time = run_target(ctl_write_fd, st_read_fd, trace_bits)

        if status_code == 9:
            print(f"Seed {seed_file} caused a timeout during the dry run")
            sys.exit(0)
        if check_crash(status_code):
            print(f"Seed {seed_file} caused a crash during the dry run")
            sys.exit(0)

        new_edge_covered, coverage = check_coverage(trace_bits)
        print(f"Dry run: Seed {seed_file} covered {coverage} edges, new edges: {new_edge_covered}")

        new_seed = Seed(seed_path, i, coverage, exec_time)
        seed_queue.append(new_seed)
        if new_edge_covered:
            feedback.save_seed(new_seed, conf)

    print("Dry run finished. Now starting the fuzzing loop...")
    iteration = 0
    while True:
        selected_seed = select_next_seed(seed_queue)
        if not selected_seed:
            print("No seeds available, exiting fuzzing loop")
            break

        power_schedule = get_power_schedule(selected_seed)

        for i in range(0, power_schedule):
            iteration += 1
            havoc_mutation(conf, selected_seed)
            if not os.path.exists(conf['current_input']):
                print(f"Warning: {conf['current_input']} does not exist, skipping")
                continue
            status_code, exec_time = run_target(ctl_write_fd, st_read_fd, trace_bits)

            if status_code == 9:
                print(f"Iteration {iteration}: Timeout, skipping this input")
                continue
            if check_crash(status_code):
                print(f"Iteration {iteration}: Found a crash, status code is {status_code}")
                crash_index = len(crash_queue)
                new_crash_filename = f"crash_{crash_index}"
                new_crash_path = os.path.join(conf['crash_folder'], new_crash_filename)
                shutil.copyfile(conf['current_input'], new_crash_path)
                crash_queue.append(new_crash_filename)
                continue

            new_edge_covered, coverage = check_coverage(trace_bits)
            print(f"Iteration {iteration}: Seed {selected_seed.path} covered {coverage} edges, new edges: {new_edge_covered}")

            if new_edge_covered:
                print("Found new coverage!")
                seed_index = len(seed_queue)
                new_seed_filename = f"seed_{seed_index}"
                new_seed_path = os.path.join(conf['queue_folder'], new_seed_filename)
                new_seed = Seed(conf['current_input'], seed_index, coverage, exec_time)
                feedback.save_seed(new_seed, conf)
                seed_queue.append(new_seed)

def main():
    print("====== Welcome to use Mini-Lop ======")

    parser = argparse.ArgumentParser(description='Mini-Lop: A lightweight grey-box fuzzer')
    parser.add_argument('--config', '-c', required=True, help='Path to config file', type=str)
    args = parser.parse_args()
    config_path = os.path.abspath(args.config)

    config_valid, conf = parse_config(config_path)
    if not config_valid or not all(key in conf for key in ['target', 'target_args', 'seeds_folder', 'queue_folder', 'crash_folder', 'current_input']):
        print("Config file is not valid or missing required fields")
        return

    libc = get_libc()
    shmid, trace_bits = setup_shm(libc)
    os.environ[SHM_ENV_VAR] = str(shmid)
    clear_shm(trace_bits)

    signal.signal(signal.SIGINT, signal_handler)
    (st_read_fd, st_write_fd) = os.pipe()
    (ctl_read_fd, ctl_write_fd) = os.pipe()

    child_pid = os.fork()
    if child_pid == 0:
        run_forkserver(conf, ctl_read_fd, st_write_fd)
    else:
        run_fuzzing(conf, st_read_fd, ctl_write_fd, trace_bits)

if __name__ == '__main__':
    main() 