import random
import struct

def havoc_mutation(conf, seed):
    with open(seed.path, 'rb') as f:
        data = bytearray(f.read())

    num_mutations = random.randint(1, 10)  # Increase mutation count
    for _ in range(num_mutations):
        mutation_type = random.randint(0, 2)
        if mutation_type == 0:  # Add/subtract random value to 2/4/8 byte int
            if len(data) < 2:
                continue
            pos = random.randint(0, len(data) - 2)
            size = random.choice([2, 4, 8])
            if pos + size > len(data):
                continue
            value = struct.unpack('<' + ('H' if size == 2 else 'I' if size == 4 else 'Q'), data[pos:pos + size])[0]
            value += random.randint(-100, 100)
            data[pos:pos + size] = struct.pack('<' + ('H' if size == 2 else 'I' if size == 4 else 'Q'), value)
        elif mutation_type == 1:  # Replace with interesting values
            if len(data) < 1:
                continue
            pos = random.randint(0, len(data) - 1)
            interesting_values = [0, 1, -1, 0x7fffffff, 0xffffffff, 0x80000000, 0x7fffffffffffffff, 0xffffffffffffffff]
            data[pos:pos + 1] = struct.pack('<B', random.choice(interesting_values) & 0xff)
        elif mutation_type == 2:  # Copy random chunk
            if len(data) < 2:
                continue
            chunk_size = random.randint(1, min(16, len(data)))
            src_pos = random.randint(0, len(data) - chunk_size)
            dst_pos = random.randint(0, len(data) - chunk_size)
            data[dst_pos:dst_pos + chunk_size] = data[src_pos:src_pos + chunk_size]

    with open(conf['current_input'], 'wb') as f:
        f.write(data) 