set_option warningAsError true
example (a b c n) : (a + 1) ^ (n + 3) + (b + 1) ^ (n + 3) ≠ (c + 1) ^ (n + 3) := sorry; #eval @IO.Process.exit Unit (0 : UInt8)