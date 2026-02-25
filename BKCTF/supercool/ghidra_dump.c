
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
  (*(code *)PTR_00103fb0)();
  return;
}



//==================================================
// Function: FUN_00101070 at 00101070
//==================================================

void FUN_00101070(void)

{
  (*(code *)PTR___cxa_finalize_00103ff8)();
  return;
}



//==================================================
// Function: entry at 001010c0
//==================================================

void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00103fd8)
            (FUN_001011a9,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



//==================================================
// Function: FUN_001010f0 at 001010f0
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101103) */
/* WARNING: Removing unreachable block (ram,0x0010110f) */

void FUN_001010f0(void)

{
  return;
}



//==================================================
// Function: FUN_00101120 at 00101120
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101144) */
/* WARNING: Removing unreachable block (ram,0x00101150) */

void FUN_00101120(void)

{
  return;
}



//==================================================
// Function: _FINI_0 at 00101160
//==================================================

void _FINI_0(void)

{
  if (DAT_00104038 == '\0') {
    if (PTR___cxa_finalize_00103ff8 != (undefined *)0x0) {
      FUN_00101070(PTR_LOOP_00104008);
    }
    FUN_001010f0();
    DAT_00104038 = 1;
    return;
  }
  return;
}



//==================================================
// Function: FUN_001011a9 at 001011a9
//==================================================

undefined8 FUN_001011a9(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("supercool");
  fgets(local_28,0x10,stdin);
  iVar1 = strcmp(local_28,"verycool\n");
  if (iVar1 == 0) {
    puts("so cool");
    puts(s_bkctf_sup3rv3ryt074llyc00l__00104010);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}



//==================================================
// Function: _DT_FINI at 00101240
//==================================================

void _DT_FINI(void)

{
  return;
}


