
//==================================================
// Function: _init at 00101000
//==================================================

int _init(EVP_PKEY_CTX *ctx)

{
  undefined *puVar1;
  
  puVar1 = PTR___gmon_start___00103fe8;
  if (PTR___gmon_start___00103fe8 != (undefined *)0x0) {
    puVar1 = (undefined *)(*(code *)PTR___gmon_start___00103fe8)();
  }
  return (int)puVar1;
}



//==================================================
// Function: FUN_00101020 at 00101020
//==================================================

void FUN_00101020(void)

{
  (*(code *)PTR_00104010)();
  return;
}



//==================================================
// Function: FUN_001010d0 at 001010d0
//==================================================

void FUN_001010d0(void)

{
  (*(code *)PTR___cxa_finalize_00103ff8)();
  return;
}



//==================================================
// Function: FUN_00101170 at 00101170
//==================================================

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00101170(void)

{
  (*_DAT_00104060)();
  return;
}



//==================================================
// Function: _start at 00101180
//==================================================

void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00103fe0)
            (main,param_2,&stack0x00000008,__libc_csu_init,__libc_csu_fini,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



//==================================================
// Function: deregister_tm_clones at 001011b0
//==================================================

/* WARNING: Removing unreachable block (ram,0x001011c3) */
/* WARNING: Removing unreachable block (ram,0x001011cf) */

void deregister_tm_clones(void)

{
  return;
}



//==================================================
// Function: register_tm_clones at 001011e0
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101204) */
/* WARNING: Removing unreachable block (ram,0x00101210) */

void register_tm_clones(void)

{
  return;
}



//==================================================
// Function: __do_global_dtors_aux at 00101220
//==================================================

void __do_global_dtors_aux(void)

{
  if (completed_8061 == '\0') {
    if (PTR___cxa_finalize_00103ff8 != (undefined *)0x0) {
      FUN_001010d0(__dso_handle);
    }
    deregister_tm_clones();
    completed_8061 = 1;
    return;
  }
  return;
}



//==================================================
// Function: getsIndex at 00101269
//==================================================

undefined8 getsIndex(void)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined8 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = __isoc99_scanf(&DAT_00102008,&local_18);
  getchar();
  if (iVar1 != 1) {
    local_18 = 0xffffffffffffffff;
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return local_18;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}



//==================================================
// Function: readBin at 001012cd
//==================================================

void readBin(void)

{
  long lVar1;
  long lVar2;
  long in_FS_OFFSET;
  undefined1 *local_70;
  undefined1 *local_58 [4];
  undefined1 *local_38;
  undefined1 *local_30;
  undefined1 *local_28;
  undefined1 *local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_58[0] = (undefined1 *)&bin0;
  local_58[1] = bin1;
  local_58[2] = bin2;
  local_58[3] = bin3;
  local_38 = bin4;
  local_30 = bin5;
  local_28 = bin6;
  local_20 = bin7;
  printf("Which bin do you want to get?\n> ");
  lVar1 = getsIndex();
  if ((lVar1 < 0) || (7 < lVar1)) {
    puts("Invalid index");
    FUN_00101170(1);
  }
  printf("What do you want to get the bin as ?\n1. Integer\n2. Float\n3. String\n4. Pointer\n> ");
  lVar2 = getsIndex();
  if (lVar2 < 0) {
    puts("Invalid index");
    FUN_00101170(1);
  }
  local_70 = *(undefined1 **)local_58[lVar1];
  if (lVar2 == 4) {
    readFormat = CONCAT13(readFormat._3_1_,0x7025);
    goto LAB_00101457;
  }
  if (lVar2 < 5) {
    if (lVar2 == 3) {
      readFormat = CONCAT13(readFormat._3_1_,0x7325);
      local_70 = local_58[lVar1];
      goto LAB_00101457;
    }
    if (lVar2 < 4) {
      if (lVar2 == 1) {
        readFormat = CONCAT13(readFormat._3_1_,0x6425);
        goto LAB_00101457;
      }
      if (lVar2 == 2) {
        readFormat = 0x666c25;
        goto LAB_00101457;
      }
    }
  }
  puts("Not an option");
LAB_00101457:
  printf((char *)&readFormat,local_70);
  putchar(10);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}



//==================================================
// Function: writeBin at 00101490
//==================================================

void writeBin(void)

{
  uint uVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  uint local_64;
  int local_60;
  undefined1 *local_58 [4];
  undefined1 *local_38;
  undefined1 *local_30;
  undefined1 *local_28;
  undefined1 *local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_64 = 8;
  local_58[0] = (undefined1 *)&bin0;
  local_58[1] = bin1;
  local_58[2] = bin2;
  local_58[3] = bin3;
  local_38 = bin4;
  local_30 = bin5;
  local_28 = bin6;
  local_20 = bin7;
  printf("Which bin do you want to write to?\n> ");
  uVar1 = getsIndex();
  if (((int)uVar1 < 0) || (7 < (int)uVar1)) {
    puts("Invalid index");
    FUN_00101170(1);
  }
  for (local_60 = 0; local_60 < (int)uVar1; local_60 = local_60 + 1) {
    local_64 = local_64 << 1;
  }
  printf("Write to bin%d (Max %d bytes)\n> ",(ulong)uVar1,(ulong)local_64);
  gets(local_58[(int)uVar1]);
  sVar2 = strlen(local_58[(int)uVar1]);
  if ((ulong)(long)(int)local_64 < sVar2) {
    puts(skillIssue);
    FUN_00101170(1);
  }
  putchar(10);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: main at 001015e6
//==================================================

void main(void)

{
  int iVar1;
  
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  do {
    while( true ) {
      puts("1. Get bin");
      puts("2. Write bin");
      puts("3. Exit");
      printf("> ");
      iVar1 = getsIndex();
      if (iVar1 < 0) {
        puts("Invalid index");
        FUN_00101170(1);
      }
      if (iVar1 == 3) break;
      if (3 < iVar1) goto LAB_001016bb;
      if (iVar1 == 1) {
        readBin();
      }
      else {
        if (iVar1 != 2) goto LAB_001016bb;
        writeBin();
      }
    }
    FUN_00101170(0);
LAB_001016bb:
    puts("Not an option");
  } while( true );
}



//==================================================
// Function: __libc_csu_init at 001016d0
//==================================================

void __libc_csu_init(EVP_PKEY_CTX *param_1,undefined8 param_2,undefined8 param_3)

{
  long lVar1;
  
  _init(param_1);
  lVar1 = 0;
  do {
    (*(code *)(&__frame_dummy_init_array_entry)[lVar1])((ulong)param_1 & 0xffffffff,param_2,param_3)
    ;
    lVar1 = lVar1 + 1;
  } while (lVar1 != 1);
  return;
}



//==================================================
// Function: __libc_csu_fini at 00101740
//==================================================

void __libc_csu_fini(void)

{
  return;
}



//==================================================
// Function: _fini at 00101748
//==================================================

void _fini(void)

{
  return;
}


