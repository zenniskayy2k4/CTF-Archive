import socket
import json
import random
import time

HOST = "chal.sunshinectf.games"
PORT = 25201

POP_SIZE = 100
GENE_LEN = 10
TOP_K = 10          # Giữ lại top 10 cá thể tốt nhất
MUTATION_RATE = 0.05  # Đột biến nhẹ hơn để tránh phá gene tốt

def random_gene():
    return [random.random() for _ in range(GENE_LEN)]

def crossover(g1, g2):
    cut = random.randint(1, GENE_LEN - 1)
    return g1[:cut] + g2[cut:]

def mutate(gene):
    for i in range(GENE_LEN):
        if random.random() < MUTATION_RATE:
            gene[i] = random.random()
    return gene

def evolve(population, scores):
    ranked = sorted(zip(population, scores), key=lambda x: x[1], reverse=True)
    parents = [x[0] for x in ranked[:TOP_K]]

    new_pop = parents.copy()
    while len(new_pop) < POP_SIZE:
        p1 = random.choice(parents)
        p2 = random.choice(parents)
        child = crossover(p1, p2)
        child = mutate(child)
        new_pop.append(child)
    return new_pop

def recv_multi_json(sock):
    """Nhận nhiều JSON hoặc flag text từ socket"""
    raw = sock.recv(100000).decode()
    lines = [l.strip() for l in raw.split("\n") if l.strip()]
    objs = []
    for line in lines:
        try:
            objs.append(json.loads(line))
        except json.JSONDecodeError:
            print("[FLAG or RAW]", line)
    return objs

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    welcome = s.recv(4096).decode()
    print("[WELCOME]", welcome.strip())

    population = [random_gene() for _ in range(POP_SIZE)]

    for gen in range(100):
        s.sendall((json.dumps({"samples": population}) + "\n").encode())
        responses = recv_multi_json(s)
        if not responses:
            print("[!] No JSON response, maybe flag above.")
            break

        # Có thể có nhiều JSON, lấy cái cuối (thường là generation info)
        data = responses[-1]
        avg = data.get("average", 0)
        scores = data.get("scores", [0]*POP_SIZE)

        best_score = max(scores)
        best_idx = scores.index(best_score)
        best_gene = population[best_idx]

        print(f"[GEN {gen+1:02d}] avg={avg:.5f}, best={best_score:.5f}")

        # Nếu tìm được gene đủ tốt thì clone 100 lần để submit flag
        if best_score >= 0.95:
            print("[+] Found optimal gene! Cloning and submitting for flag...")
            final_population = [best_gene for _ in range(POP_SIZE)]
            s.sendall((json.dumps({"samples": final_population}) + "\n").encode())
            flag_resp = s.recv(10000).decode()
            print("[FLAG RESPONSE]", flag_resp)
            break

        # Tiến hóa cho thế hệ tiếp theo
        population = evolve(population, scores)
        time.sleep(0.05)
