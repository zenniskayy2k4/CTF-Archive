
//==================================================
// Function: _DT_INIT at 00101000
//==================================================

void _DT_INIT(void)

{
  if (PTR___gmon_start___00103fe8 != (undefined *)0x0) {
    (*(code *)PTR___gmon_start___00103fe8)();
  }
  return;
}



//==================================================
// Function: FUN_00101020 at 00101020
//==================================================

void FUN_00101020(void)

{
  (*(code *)PTR_00103f70)();
  return;
}



//==================================================
// Function: FUN_001010f0 at 001010f0
//==================================================

void FUN_001010f0(void)

{
  (*(code *)PTR___cxa_finalize_00103ff8)();
  return;
}



//==================================================
// Function: entry at 001011c0
//==================================================

void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00103fd8)
            (FUN_001016cd,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



//==================================================
// Function: FUN_001011f0 at 001011f0
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101203) */
/* WARNING: Removing unreachable block (ram,0x0010120f) */

void FUN_001011f0(void)

{
  return;
}



//==================================================
// Function: FUN_00101220 at 00101220
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101244) */
/* WARNING: Removing unreachable block (ram,0x00101250) */

void FUN_00101220(void)

{
  return;
}



//==================================================
// Function: _FINI_0 at 00101260
//==================================================

void _FINI_0(void)

{
  if (DAT_00104018 == '\0') {
    if (PTR___cxa_finalize_00103ff8 != (undefined *)0x0) {
      FUN_001010f0(PTR_LOOP_00104008);
    }
    FUN_001011f0();
    DAT_00104018 = 1;
    return;
  }
  return;
}



//==================================================
// Function: FUN_001012a9 at 001012a9
//==================================================

ulong FUN_001012a9(long param_1,ulong param_2,ulong param_3)

{
  undefined8 local_18;
  undefined8 local_10;
  
  local_18 = param_3;
  for (local_10 = 0; local_10 < param_2; local_10 = local_10 + 1) {
    local_18 = (local_18 ^ *(byte *)(local_10 + param_1)) * 0x100000001b3;
    local_18 = local_18 ^ local_18 >> 0x20;
  }
  return local_18;
}



//==================================================
// Function: FUN_0010131b at 0010131b
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101494) */

void FUN_0010131b(void)

{
  code *pcVar1;
  long lVar2;
  char *pcVar3;
  size_t sVar4;
  long in_FS_OFFSET;
  undefined4 local_8f;
  undefined3 uStack_8b;
  char local_88 [104];
  undefined8 local_20;
  
  local_20 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  lVar2 = ptrace(PTRACE_TRACEME,0,0,0);
  if (lVar2 < 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  raise(0x13);
  memset(local_88,0,100);
  local_8f = 0x73736150;
  uStack_8b = 0x203a;
  write(1,&local_8f,6);
  pcVar3 = fgets(local_88,100,stdin);
  if (pcVar3 != (char *)0x0) {
    sVar4 = strcspn(local_88,"\n");
    local_88[sVar4] = '\0';
    sVar4 = strlen(local_88);
    if (sVar4 == 0x28) {
      FUN_001012a9(local_88,1,0xcbf29ce484222325);
                    /* WARNING: Does not return */
      pcVar1 = (code *)invalidInstructionException();
      (*pcVar1)();
    }
    puts("Oh sure, here is your flag: 0xfun{1_10v3_M1LF}");
                    /* WARNING: Subroutine does not return */
    exit(99);
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}



//==================================================
// Function: FUN_001014ad at 001014ad
//==================================================

void FUN_001014ad(uint param_1)

{
  long lVar1;
  long *plVar2;
  long *plVar3;
  long in_FS_OFFSET;
  uint local_248;
  int local_244;
  long local_240;
  undefined1 local_238 [80];
  long local_1e8;
  long local_1b8;
  long local_158 [41];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  plVar2 = &DAT_001020a0;
  plVar3 = local_158;
  for (lVar1 = 0x28; lVar1 != 0; lVar1 = lVar1 + -1) {
    *plVar3 = *plVar2;
    plVar2 = plVar2 + 1;
    plVar3 = plVar3 + 1;
  }
  waitpid(param_1,(int *)&local_248,0);
  while( true ) {
    while( true ) {
      if ((local_248 & 0xff) != 0x7f) {
        if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
        return;
      }
      if ((local_248 & 0xff00) == 0x400) break;
      ptrace(PTRACE_CONT,(ulong)param_1,0,(ulong)((int)local_248 >> 8 & 0xff));
      waitpid(param_1,(int *)&local_248,0);
    }
    ptrace(PTRACE_GETREGS,(ulong)param_1,0,local_238);
    local_240 = local_1e8;
    local_244 = (int)local_238._40_8_;
    if ((local_244 < 0) || (0x27 < local_244)) break;
    if (local_1e8 != local_158[local_244]) {
      ptrace(PTRACE_KILL,(ulong)param_1,0,0);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    local_1b8 = local_1b8 + 2;
    ptrace(PTRACE_SETREGS,(ulong)param_1,0,local_238);
    ptrace(PTRACE_CONT,(ulong)param_1,0,0);
    waitpid(param_1,(int *)&local_248,0);
  }
  ptrace(PTRACE_KILL,(ulong)param_1,0,0);
                    /* WARNING: Subroutine does not return */
  exit(1);
}



//==================================================
// Function: FUN_001016cd at 001016cd
//==================================================

undefined8 FUN_001016cd(void)

{
  __pid_t _Var1;
  
  _Var1 = fork();
  if (_Var1 == 0) {
    FUN_0010131b();
  }
  else {
    FUN_001014ad(_Var1);
  }
  return 0;
}



//==================================================
// Function: _DT_FINI at 00101700
//==================================================

void _DT_FINI(void)

{
  return;
}


