
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
  (*(code *)PTR_00103f48)();
  return;
}



//==================================================
// Function: FUN_00101140 at 00101140
//==================================================

void FUN_00101140(void)

{
  (*(code *)PTR___cxa_finalize_00103ff8)();
  return;
}



//==================================================
// Function: entry at 00101260
//==================================================

void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00103fd8)
            (FUN_001015fd,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



//==================================================
// Function: FUN_00101290 at 00101290
//==================================================

/* WARNING: Removing unreachable block (ram,0x001012a3) */
/* WARNING: Removing unreachable block (ram,0x001012af) */

void FUN_00101290(void)

{
  return;
}



//==================================================
// Function: FUN_001012c0 at 001012c0
//==================================================

/* WARNING: Removing unreachable block (ram,0x001012e4) */
/* WARNING: Removing unreachable block (ram,0x001012f0) */

void FUN_001012c0(void)

{
  return;
}



//==================================================
// Function: _FINI_0 at 00101300
//==================================================

void _FINI_0(void)

{
  if (DAT_00104048 == '\0') {
    if (PTR___cxa_finalize_00103ff8 != (undefined *)0x0) {
      FUN_00101140(PTR_LOOP_00104008);
    }
    FUN_00101290();
    DAT_00104048 = 1;
    return;
  }
  return;
}



//==================================================
// Function: FUN_00101349 at 00101349
//==================================================

uint FUN_00101349(byte param_1,byte param_2)

{
  return (uint)param_1 << (8 - (param_2 & 7) & 0x1f) | (int)(uint)param_1 >> (param_2 & 7);
}



//==================================================
// Function: FUN_00101382 at 00101382
//==================================================

undefined8 FUN_00101382(char *param_1,undefined8 param_2,int param_3)

{
  char *pcVar1;
  long in_FS_OFFSET;
  char local_103a;
  byte local_1039;
  int local_1038;
  int local_1034;
  ulong local_1030;
  ssize_t local_1028;
  char *local_1020;
  char local_1018 [4104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if ((param_3 == 0) && (local_1038 = open(param_1,0), -1 < local_1038)) {
    local_1028 = read(local_1038,&local_103a,1);
    if ((local_1028 == 1) && (local_103a == 'g')) {
      pcVar1 = strrchr(param_1,0x2f);
      if (pcVar1 != (char *)0x0) {
        param_1 = pcVar1 + 1;
      }
      local_1020 = param_1;
      snprintf(local_1018,0x1000,"./decrypted/%s",param_1);
      local_1034 = open(local_1018,0x241,0x1a4);
      if (local_1034 < 0) {
        close(local_1038);
      }
      else {
        local_1030 = 0;
        while (local_1028 = read(local_1038,&local_103a,1), local_1028 == 1) {
          local_1039 = FUN_00101349(local_103a,(uint)local_1030 & 7);
          local_1039 = local_1039 ^ *(byte *)(local_1030 % DAT_00104058 + DAT_00104050);
          write(local_1034,&local_1039,1);
          local_1030 = local_1030 + 1;
        }
        close(local_1038);
        close(local_1034);
      }
    }
    else {
      close(local_1038);
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}



//==================================================
// Function: FUN_001015fd at 001015fd
//==================================================

undefined8 FUN_001015fd(void)

{
  int iVar1;
  char *pcVar2;
  undefined8 uVar3;
  size_t sVar4;
  long in_FS_OFFSET;
  stat local_14a8;
  char local_1418 [1024];
  char local_1018 [4104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts(
      "Welcome victim! If you have followed our instructions and sent five sticks of Cosair Dominator Titanium RGB 48GB DDR5 RAM to the address specified, you will have received a decryption key to recover your files."
      );
  printf("Enter decryption key: ");
  pcVar2 = fgets(local_1418,0x400,stdin);
  if (pcVar2 == (char *)0x0) {
    uVar3 = 1;
  }
  else {
    sVar4 = strcspn(local_1418,"\n");
    local_1418[sVar4] = '\0';
    DAT_00104050 = local_1418;
    DAT_00104058 = strlen(local_1418);
    if (DAT_00104058 == 0) {
      fwrite("Empty key\n",1,10,stderr);
      uVar3 = 1;
    }
    else {
      printf("Enter directory to decrypt: ");
      pcVar2 = fgets(local_1018,0x1000,stdin);
      if (pcVar2 == (char *)0x0) {
        uVar3 = 1;
      }
      else {
        sVar4 = strcspn(local_1018,"\n");
        local_1018[sVar4] = '\0';
        iVar1 = stat(local_1018,&local_14a8);
        if ((iVar1 == 0) && ((local_14a8.st_mode & 0xf000) == 0x4000)) {
          puts("Decrypting...");
          mkdir("./decrypted",0x1ed);
          iVar1 = nftw(local_1018,FUN_00101382,0x10,0);
          if (iVar1 == 0) {
            puts("Thanks for the free RAM!");
            uVar3 = 0;
          }
          else {
            perror("nftw");
            uVar3 = 1;
          }
        }
        else {
          fwrite("Invalid directory\n",1,0x12,stderr);
          uVar3 = 1;
        }
      }
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar3;
}



//==================================================
// Function: _DT_FINI at 00101834
//==================================================

void _DT_FINI(void)

{
  return;
}


