# Solver (simplified, adapted from what mình chạy)
import numpy as np, time

arr = [
    np.array([  17.33884894,   81.37080239, -143.96234736,  123.95164171]),
    np.array([ 168.34743674,  100.91788802, -135.90959582,  146.37617105]),
    np.array([ 157.94860314,   49.20197906, -155.2459834 ,   73.56498047]),
    np.array([   9.1131532 ,   49.36829422, -117.25335109,  181.11592151]),
    np.array([ 223.96684757,  -12.0765699 , -126.07584525,  125.88335439]),
    np.array([ 80.13452478,  40.78304285, -51.15180044, 143.18760932]),
    np.array([ 251.41332497,   48.04296984, -128.92087521,   68.4732401 ]),
    np.array([108.94539496,  -0.41865393, -53.94228136, 100.98194223]),
    np.array([183.06845007,  27.56200727, -52.57316992,  44.05723383]),
    np.array([ 96.56452698,  60.67582903, -76.44584757,  40.88253203])
]
Y = np.array(arr).T
n = Y.shape[1]

allowed_inner = list("abcdefghijklmnopqrstuvwxyz0123456789_") + ['}']
vals_allowed = np.array([ord(c) for c in allowed_inner], dtype=int)

# precompute combos once (size = len(vals_allowed)**3)
g1,g2,g3 = np.meshgrid(vals_allowed, vals_allowed, vals_allowed, indexing='ij')
X_all = np.vstack([g1.ravel(), g2.ravel(), g3.ravel()]).astype(float)

def als_initial(Y, seed=0, iters=200):
    rng = np.random.RandomState(seed)
    V = rng.uniform(0,255,size=(4,n))
    V[1:,:] = rng.randint(32,127,size=(3,n))
    for _ in range(iters):
        V_aug = np.vstack([V, np.ones((1,n))])
        M_aug = Y @ V_aug.T @ np.linalg.pinv(V_aug @ V_aug.T)
        M = M_aug[:,:4]; t = M_aug[:,4]
        for i in range(n):
            V[:,i] = np.linalg.pinv(M) @ (Y[:,i] - t)
    return M, t, V

def top_k_candidates_for_sample(y, M, t, X_all, K=200, require_fixed=None):
    A0 = M[:,0]; A123 = M[:,1:4]
    w = A0 @ A123
    denom = float(A0 @ A0) + 1e-12
    y_minus_t = y - t
    WX = w @ X_all
    numer_const = float(A0 @ y_minus_t)
    v0s = (numer_const - WX) / denom
    preds = (A0[:,None] * v0s[None,:]) + (A123 @ X_all) + t[:,None]
    resids = np.linalg.norm(preds - y[:,None], axis=0)
    if require_fixed:
        mask = np.ones(resids.shape, dtype=bool)
        for pos, val in require_fixed.items():
            mask &= (X_all[pos,:] == val)
        resids = np.where(mask, resids, np.inf)
    idxs = np.argpartition(resids, min(K, resids.size)-1)[:K]
    idxs = idxs[np.argsort(resids[idxs])]
    return [((int(X_all[0,i]), int(X_all[1,i]), int(X_all[2,i])), float(v0s[i]), float(resids[i])) for i in idxs]

def beam_search_from_topk(topk_per_sample, beam_width=1000, time_limit=30.0):
    start = time.time()
    beam = [(0.0, 0, [], 0, None)]
    for i in range(n):
        new_beam=[]
        cand_list = topk_per_sample[i]
        if cand_list is None: return []
        for score, idx, triples, brace_count, brace_pos in beam:
            for triple, v0, resid in cand_list:
                local_braces = [j for j,ch in enumerate(triple) if ch == 125]
                valid = True
                for pos in local_braces:
                    if i < 1 or (i == 1 and pos <= 1):
                        valid = False; break
                if not valid: continue
                new_brace_count = brace_count + len(local_braces)
                if new_brace_count > 1: continue
                new_triples = triples + [triple]
                new_score = score + resid
                new_beam.append((new_score, i+1, new_triples, new_brace_count, (i, local_braces[0]) if local_braces else None))
        if not new_beam: return []
        new_beam.sort(key=lambda x: x[0])
        beam = new_beam[:beam_width]
        if time.time() - start > time_limit: break
    return beam

# --- Parameters you can increase on a better machine ---
seeds = [3,7,11,17,23]
K = 300              # increase to 500+ for deeper search
beam_width = 2000    # increase for better coverage
time_limit = 120.0   # seconds for beam
refine_iters = 8

best = None
tstart = time.time()
for seed in seeds:
    M,t,V = als_initial(Y, seed=seed, iters=240)
    topk_per_sample = []
    for i in range(n):
        if i==0:
            req = {0:ord('i'),1:ord('c'),2:ord('t')}
        elif i==1:
            req = {0:ord('f'),1:ord('{')}
        else:
            req = None
        topk_per_sample.append(top_k_candidates_for_sample(Y[:,i], M, t, X_all, K=K, require_fixed=req))
    beams = beam_search_from_topk(topk_per_sample, beam_width=beam_width, time_limit=time_limit)
    for score, idx, triples, brace_count, brace_pos in beams[:400]:
        Vcand = np.zeros((4,n))
        for i in range(n):
            Vcand[1:4,i] = np.array(triples[i])
        V_aug = np.vstack([Vcand, np.ones((1,n))])
        M_aug = Y @ V_aug.T @ np.linalg.pinv(V_aug @ V_aug.T)
        M_c = M_aug[:,:4]; t_c = M_aug[:,4]
        for i in range(n):
            Vcand[0,i] = float((np.linalg.pinv(M_c) @ (Y[:,i] - t_c))[0])
        # light refine: repeat a few passes over blocks
        for _ in range(refine_iters):
            for i in range(n):
                # top 30 candidates per block under current M_c,t_c
                topk_i = top_k_candidates_for_sample(Y[:,i], M_c, t_c, X_all, K=30)
                cur_tri = tuple(int(round(x)) for x in Vcand[1:4,i])
                for tri, v0, r in topk_i:
                    if tri == cur_tri: continue
                    Vtrial = Vcand.copy(); Vtrial[1:4,i] = np.array(tri)
                    V_aug2 = np.vstack([Vtrial, np.ones((1,n))])
                    M2 = (Y @ V_aug2.T @ np.linalg.pinv(V_aug2 @ V_aug2.T))[:,:4]
                    t2 = (Y @ V_aug2.T @ np.linalg.pinv(V_aug2 @ V_aug2.T))[:,4]
                    for j in range(n):
                        Vtrial[0,j] = float((np.linalg.pinv(M2) @ (Y[:,j] - t2))[0])
                    # compute residual
                    resid = sum(np.linalg.norm(M2 @ Vtrial[:,j] + t2 - Y[:,j]) for j in range(n))
                    if resid < (best[0] if best else 1e18):
                        flag_try = ''.join(''.join(chr(int(round(x))) for x in Vtrial[1:4,i]) for i in range(n))
                        if flag_try.startswith("ictf{") and flag_try.count('}')==1 and flag_try.index('}')>4:
                            best = (resid, flag_try)
    if time.time() - tstart > 180: break

print("best candidate:", best)
