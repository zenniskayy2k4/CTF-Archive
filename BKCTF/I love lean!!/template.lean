set_option warningAsError true

def mem_effecient_mod_exp (b e m c : Nat) : Nat :=
    if e > 0 then
      mem_effecient_mod_exp b (e - 1) m ((b * c) % m)
    else
      c % m

theorem it_works (b e m : Nat) : mem_effecient_mod_exp b e m 1 = (b ^ e) % m := by
  have h : ∀ e' c', mem_effecient_mod_exp b e' m c' = (c' * b ^ e') % m := by
    intro e'
    induction e' with
    | zero =>
      intro c'
      unfold mem_effecient_mod_exp
      simp
    | succ e' ih =>
      intro c'
      unfold mem_effecient_mod_exp
      have h_pos : e' + 1 > 0 := by omega
      have h_sub : e' + 1 - 1 = e' := by omega
      simp [h_pos, h_sub]
      rw [ih]
      have h_mod : (b * c' % m * b ^ e') % m = (b * c' * b ^ e') % m := by
        calc (b * c' % m * b ^ e') % m
          _ = (b * c' % m % m * (b ^ e' % m)) % m := by rw [Nat.mul_mod]
          _ = (b * c' % m * (b ^ e' % m)) % m := by rw [Nat.mod_mod]
          _ = (b * c' * b ^ e') % m := by rw [← Nat.mul_mod]
      rw [h_mod, Nat.pow_succ]
      congr 1
      ac_rfl
  rw [h e 1]
  simp


