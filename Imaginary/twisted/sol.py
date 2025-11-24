import numpy as np
from scipy.optimize import basinhopping

# Output from output.txt
output = np.array([
    [17.33884894, 81.37080239, -143.96234736, 123.95164171],
    [168.34743674, 100.91788802, -135.90959582, 146.37617105],
    [157.94860314, 49.20197906, -155.2459834, 73.56498047],
    [9.1131532, 49.36829422, -117.25335109, 181.11592151],
    [223.96684757, -12.0765699, -126.07584525, 125.88335439],
    [80.13452478, 40.78304285, -51.15180044, 143.18760932],
    [251.41332497, 48.04296984, -128.92087521, 68.4732401],
    [108.94539496, -0.41865393, -53.94228136, 100.98194223],
    [183.06845007, 27.56200727, -52.57316992, 44.05723383],
    [96.56452698, 60.67582903, -76.44584757, 40.88253203]
])

s = 1.25
sigma = 0.22

# Known prefix: ictf{
known_prefix = np.array([105, 99, 116, 102, 123])  # ASCII for i, c, t, f, {

def conj(q):
    return np.array([q[0], -q[1], -q[2], -q[3]])

def mul(q1, q2):
    w1, x1, y1, z1 = q1
    w2, x2, y2, z2 = q2
    return np.array([
        w1*w2 - x1*x2 - y1*y2 - z1*z2,
        w1*x2 + x1*w2 + y1*z2 - z1*y2,
        w1*y2 - x1*z2 + y1*w2 + z1*x2,
        w1*z2 + x1*y2 - y1*x2 + z1*w2
    ])

def rotate(v, q):
    return mul(mul(q, v), conj(q))

def orthogonalize(A):
    Q, _ = np.linalg.qr(A.reshape(3, 3))
    if np.linalg.det(Q) < 0:
        Q[:, 0] = -Q[:, 0]
    return Q.flatten()

def cost(params):
    r = params[:4]
    r = r / np.linalg.norm(r)  # Unit quaternion
    a = orthogonalize(params[4:13]).reshape(3, 3)
    t = params[13:16]
    
    total_err = 0.0
    for i, vec in enumerate(output):
        w, x, y, z = vec
        # Reverse transformations
        v = np.array([x, y, z]) - t
        v = v / s
        v = a.T @ v
        v_quat = np.concatenate(([w], v))
        v_rot = rotate(v_quat, conj(r))
        cand = v_rot[1:]
        rounded = np.round(cand)
        # Check ASCII range [32, 126]
        invalid = np.logical_or(rounded < 32, rounded > 126)
        total_err += np.sum((cand - rounded) ** 2)
        total_err += np.sum(invalid) * 1000  # Heavy penalty for invalid ASCII
        # Enforce known prefix for first 5 characters
        if i == 0:
            total_err += np.sum((rounded[:2] - known_prefix[:2]) ** 2) * 10
        elif i == 1:
            total_err += np.sum((rounded[:3] - known_prefix[2:5]) ** 2) * 10
    return total_err

# Bounds
bounds = [(-10, 10)] * 4 + [(-10, 10)] * 9 + [(-90, 90)] * 3

# Initial guess
x0 = np.concatenate([
    np.random.randn(4),
    np.random.randn(9),
    np.random.uniform(-90, 90, 3)
])

# Optimization
minimizer_kwargs = {"method": "L-BFGS-B", "bounds": bounds}
res = basinhopping(cost, x0, niter=1000, minimizer_kwargs=minimizer_kwargs, seed=42)

print("Min cost:", res.fun)

# Extract parameters
r = res.x[:4]
r = r / np.linalg.norm(r)
a = orthogonalize(res.x[4:13]).reshape(3, 3)
t = res.x[13:16]

# Recover flag
flag = ''
for i, vec in enumerate(output):
    w, x, y, z = vec
    v = np.array([x, y, z]) - t
    v = v / s
    v = a.T @ v
    v_quat = np.concatenate(([w], v))
    v_rot = rotate(v_quat, conj(r))
    rounded = np.round(v_rot[1:]).astype(int)
    print(f"Rounded values for group {i+1}: {rounded}")
    for val in rounded:
        if 32 <= val <= 126:
            flag += chr(val)
        else:
            print(f"Warning: Invalid ASCII value {val} in group {i+1}")
            flag += '?'
print("Flag:", flag)

# If flag ends with '0', suggest trimming padding
if flag.endswith('0'):
    print("Flag with padding removed:", flag.rstrip('0'))