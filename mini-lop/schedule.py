import random
import os

def select_next_seed(seed_queue):
    if not seed_queue:
        return None
    scored_seeds = []
    for seed in seed_queue:
        size = os.path.getsize(seed.path)
        coverage = seed.coverage if hasattr(seed, 'coverage') else 0
        score = coverage / (size + 1)  # Avoid division by zero
        scored_seeds.append((seed, score))

    scored_seeds.sort(key=lambda x: x[1], reverse=True)
    favored = scored_seeds[:max(1, len(scored_seeds)//2)]

    for seed, _ in scored_seeds:
        seed.unmark_favored()  # Reset all seeds
    for seed, _ in favored:
        seed.mark_favored()  # Mark top seeds as favored

    favored_seeds = [seed for seed, _ in favored]
    if random.random() < 0.8 and favored_seeds:
        return random.choice(favored_seeds)
    return random.choice(seed_queue)

def get_power_schedule(seed):
    coverage = seed.coverage if hasattr(seed, 'coverage') else 1
    score = min(coverage, 100)  # Cap score to avoid excessive mutations
    chance = score / 100
    return int(1 + chance * 20)  # Scale to 1–21 mutations 