
//==================================================
// Function: _DT_INIT at 00102000
//==================================================

void _DT_INIT(void)

{
  if (PTR___gmon_start___0010afe8 != (undefined *)0x0) {
    (*(code *)PTR___gmon_start___0010afe8)();
  }
  return;
}



//==================================================
// Function: FUN_00102020 at 00102020
//==================================================

void FUN_00102020(void)

{
  (*(code *)PTR_0010ae80)();
  return;
}



//==================================================
// Function: FUN_001022d0 at 001022d0
//==================================================

void FUN_001022d0(void)

{
  (*(code *)PTR___cxa_finalize_0010aff8)();
  return;
}



//==================================================
// Function: entry at 00102580
//==================================================

void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_0010afd8)
            (FUN_00102fcf,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



//==================================================
// Function: FUN_001025b0 at 001025b0
//==================================================

/* WARNING: Removing unreachable block (ram,0x001025c3) */
/* WARNING: Removing unreachable block (ram,0x001025cf) */

void FUN_001025b0(void)

{
  return;
}



//==================================================
// Function: FUN_001025e0 at 001025e0
//==================================================

/* WARNING: Removing unreachable block (ram,0x00102604) */
/* WARNING: Removing unreachable block (ram,0x00102610) */

void FUN_001025e0(void)

{
  return;
}



//==================================================
// Function: _FINI_0 at 00102620
//==================================================

void _FINI_0(void)

{
  if (DAT_0010c288 == '\0') {
    if (PTR___cxa_finalize_0010aff8 != (undefined *)0x0) {
      FUN_001022d0(PTR_LOOP_0010b008);
    }
    FUN_001025b0();
    DAT_0010c288 = 1;
    return;
  }
  return;
}



//==================================================
// Function: FUN_00102669 at 00102669
//==================================================

undefined8 FUN_00102669(void)

{
  int __fd;
  undefined8 uVar1;
  char *pcVar2;
  long in_FS_OFFSET;
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __fd = open("/proc/version",0);
  if (__fd == -1) {
    uVar1 = 0;
  }
  else {
    local_118[0] = '\0';
    local_118[1] = '\0';
    local_118[2] = '\0';
    local_118[3] = '\0';
    local_118[4] = '\0';
    local_118[5] = '\0';
    local_118[6] = '\0';
    local_118[7] = '\0';
    local_118[8] = '\0';
    local_118[9] = '\0';
    local_118[10] = '\0';
    local_118[0xb] = '\0';
    local_118[0xc] = '\0';
    local_118[0xd] = '\0';
    local_118[0xe] = '\0';
    local_118[0xf] = '\0';
    local_118[0x10] = '\0';
    local_118[0x11] = '\0';
    local_118[0x12] = '\0';
    local_118[0x13] = '\0';
    local_118[0x14] = '\0';
    local_118[0x15] = '\0';
    local_118[0x16] = '\0';
    local_118[0x17] = '\0';
    local_118[0x18] = '\0';
    local_118[0x19] = '\0';
    local_118[0x1a] = '\0';
    local_118[0x1b] = '\0';
    local_118[0x1c] = '\0';
    local_118[0x1d] = '\0';
    local_118[0x1e] = '\0';
    local_118[0x1f] = '\0';
    local_118[0x20] = '\0';
    local_118[0x21] = '\0';
    local_118[0x22] = '\0';
    local_118[0x23] = '\0';
    local_118[0x24] = '\0';
    local_118[0x25] = '\0';
    local_118[0x26] = '\0';
    local_118[0x27] = '\0';
    local_118[0x28] = '\0';
    local_118[0x29] = '\0';
    local_118[0x2a] = '\0';
    local_118[0x2b] = '\0';
    local_118[0x2c] = '\0';
    local_118[0x2d] = '\0';
    local_118[0x2e] = '\0';
    local_118[0x2f] = '\0';
    local_118[0x30] = '\0';
    local_118[0x31] = '\0';
    local_118[0x32] = '\0';
    local_118[0x33] = '\0';
    local_118[0x34] = '\0';
    local_118[0x35] = '\0';
    local_118[0x36] = '\0';
    local_118[0x37] = '\0';
    local_118[0x38] = '\0';
    local_118[0x39] = '\0';
    local_118[0x3a] = '\0';
    local_118[0x3b] = '\0';
    local_118[0x3c] = '\0';
    local_118[0x3d] = '\0';
    local_118[0x3e] = '\0';
    local_118[0x3f] = '\0';
    local_118[0x40] = '\0';
    local_118[0x41] = '\0';
    local_118[0x42] = '\0';
    local_118[0x43] = '\0';
    local_118[0x44] = '\0';
    local_118[0x45] = '\0';
    local_118[0x46] = '\0';
    local_118[0x47] = '\0';
    local_118[0x48] = '\0';
    local_118[0x49] = '\0';
    local_118[0x4a] = '\0';
    local_118[0x4b] = '\0';
    local_118[0x4c] = '\0';
    local_118[0x4d] = '\0';
    local_118[0x4e] = '\0';
    local_118[0x4f] = '\0';
    local_118[0x50] = '\0';
    local_118[0x51] = '\0';
    local_118[0x52] = '\0';
    local_118[0x53] = '\0';
    local_118[0x54] = '\0';
    local_118[0x55] = '\0';
    local_118[0x56] = '\0';
    local_118[0x57] = '\0';
    local_118[0x58] = '\0';
    local_118[0x59] = '\0';
    local_118[0x5a] = '\0';
    local_118[0x5b] = '\0';
    local_118[0x5c] = '\0';
    local_118[0x5d] = '\0';
    local_118[0x5e] = '\0';
    local_118[0x5f] = '\0';
    local_118[0x60] = '\0';
    local_118[0x61] = '\0';
    local_118[0x62] = '\0';
    local_118[99] = '\0';
    local_118[100] = '\0';
    local_118[0x65] = '\0';
    local_118[0x66] = '\0';
    local_118[0x67] = '\0';
    local_118[0x68] = '\0';
    local_118[0x69] = '\0';
    local_118[0x6a] = '\0';
    local_118[0x6b] = '\0';
    local_118[0x6c] = '\0';
    local_118[0x6d] = '\0';
    local_118[0x6e] = '\0';
    local_118[0x6f] = '\0';
    local_118[0x70] = '\0';
    local_118[0x71] = '\0';
    local_118[0x72] = '\0';
    local_118[0x73] = '\0';
    local_118[0x74] = '\0';
    local_118[0x75] = '\0';
    local_118[0x76] = '\0';
    local_118[0x77] = '\0';
    local_118[0x78] = '\0';
    local_118[0x79] = '\0';
    local_118[0x7a] = '\0';
    local_118[0x7b] = '\0';
    local_118[0x7c] = '\0';
    local_118[0x7d] = '\0';
    local_118[0x7e] = '\0';
    local_118[0x7f] = '\0';
    local_118[0x80] = '\0';
    local_118[0x81] = '\0';
    local_118[0x82] = '\0';
    local_118[0x83] = '\0';
    local_118[0x84] = '\0';
    local_118[0x85] = '\0';
    local_118[0x86] = '\0';
    local_118[0x87] = '\0';
    local_118[0x88] = '\0';
    local_118[0x89] = '\0';
    local_118[0x8a] = '\0';
    local_118[0x8b] = '\0';
    local_118[0x8c] = '\0';
    local_118[0x8d] = '\0';
    local_118[0x8e] = '\0';
    local_118[0x8f] = '\0';
    local_118[0x90] = '\0';
    local_118[0x91] = '\0';
    local_118[0x92] = '\0';
    local_118[0x93] = '\0';
    local_118[0x94] = '\0';
    local_118[0x95] = '\0';
    local_118[0x96] = '\0';
    local_118[0x97] = '\0';
    local_118[0x98] = '\0';
    local_118[0x99] = '\0';
    local_118[0x9a] = '\0';
    local_118[0x9b] = '\0';
    local_118[0x9c] = '\0';
    local_118[0x9d] = '\0';
    local_118[0x9e] = '\0';
    local_118[0x9f] = '\0';
    local_118[0xa0] = '\0';
    local_118[0xa1] = '\0';
    local_118[0xa2] = '\0';
    local_118[0xa3] = '\0';
    local_118[0xa4] = '\0';
    local_118[0xa5] = '\0';
    local_118[0xa6] = '\0';
    local_118[0xa7] = '\0';
    local_118[0xa8] = '\0';
    local_118[0xa9] = '\0';
    local_118[0xaa] = '\0';
    local_118[0xab] = '\0';
    local_118[0xac] = '\0';
    local_118[0xad] = '\0';
    local_118[0xae] = '\0';
    local_118[0xaf] = '\0';
    local_118[0xb0] = '\0';
    local_118[0xb1] = '\0';
    local_118[0xb2] = '\0';
    local_118[0xb3] = '\0';
    local_118[0xb4] = '\0';
    local_118[0xb5] = '\0';
    local_118[0xb6] = '\0';
    local_118[0xb7] = '\0';
    local_118[0xb8] = '\0';
    local_118[0xb9] = '\0';
    local_118[0xba] = '\0';
    local_118[0xbb] = '\0';
    local_118[0xbc] = '\0';
    local_118[0xbd] = '\0';
    local_118[0xbe] = '\0';
    local_118[0xbf] = '\0';
    local_118[0xc0] = '\0';
    local_118[0xc1] = '\0';
    local_118[0xc2] = '\0';
    local_118[0xc3] = '\0';
    local_118[0xc4] = '\0';
    local_118[0xc5] = '\0';
    local_118[0xc6] = '\0';
    local_118[199] = '\0';
    local_118[200] = '\0';
    local_118[0xc9] = '\0';
    local_118[0xca] = '\0';
    local_118[0xcb] = '\0';
    local_118[0xcc] = '\0';
    local_118[0xcd] = '\0';
    local_118[0xce] = '\0';
    local_118[0xcf] = '\0';
    local_118[0xd0] = '\0';
    local_118[0xd1] = '\0';
    local_118[0xd2] = '\0';
    local_118[0xd3] = '\0';
    local_118[0xd4] = '\0';
    local_118[0xd5] = '\0';
    local_118[0xd6] = '\0';
    local_118[0xd7] = '\0';
    local_118[0xd8] = '\0';
    local_118[0xd9] = '\0';
    local_118[0xda] = '\0';
    local_118[0xdb] = '\0';
    local_118[0xdc] = '\0';
    local_118[0xdd] = '\0';
    local_118[0xde] = '\0';
    local_118[0xdf] = '\0';
    local_118[0xe0] = '\0';
    local_118[0xe1] = '\0';
    local_118[0xe2] = '\0';
    local_118[0xe3] = '\0';
    local_118[0xe4] = '\0';
    local_118[0xe5] = '\0';
    local_118[0xe6] = '\0';
    local_118[0xe7] = '\0';
    local_118[0xe8] = '\0';
    local_118[0xe9] = '\0';
    local_118[0xea] = '\0';
    local_118[0xeb] = '\0';
    local_118[0xec] = '\0';
    local_118[0xed] = '\0';
    local_118[0xee] = '\0';
    local_118[0xef] = '\0';
    local_118[0xf0] = '\0';
    local_118[0xf1] = '\0';
    local_118[0xf2] = '\0';
    local_118[0xf3] = '\0';
    local_118[0xf4] = '\0';
    local_118[0xf5] = '\0';
    local_118[0xf6] = '\0';
    local_118[0xf7] = '\0';
    local_118[0xf8] = '\0';
    local_118[0xf9] = '\0';
    local_118[0xfa] = '\0';
    local_118[0xfb] = '\0';
    local_118[0xfc] = '\0';
    local_118[0xfd] = '\0';
    local_118[0xfe] = '\0';
    local_118[0xff] = '\0';
    read(__fd,local_118,0xff);
    close(__fd);
    pcVar2 = strstr(local_118,"Microsoft");
    if (pcVar2 == (char *)0x0) {
      pcVar2 = strstr(local_118,"microsoft");
      if (pcVar2 == (char *)0x0) {
        pcVar2 = strstr(local_118,"WSL");
        if (pcVar2 == (char *)0x0) {
          uVar1 = 0;
          goto LAB_0010287e;
        }
      }
    }
    uVar1 = 1;
  }
LAB_0010287e:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar1;
}



//==================================================
// Function: FUN_00102894 at 00102894
//==================================================

undefined8 FUN_00102894(void)

{
  char cVar1;
  undefined8 uVar2;
  long lVar3;
  
  cVar1 = FUN_00102669();
  if (cVar1 == '\0') {
    lVar3 = ptrace(PTRACE_TRACEME,0,0,0);
    if (lVar3 == -1) {
      uVar2 = 1;
    }
    else {
      ptrace(PTRACE_DETACH,0,0,0);
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



//==================================================
// Function: FUN_00102901 at 00102901
//==================================================

undefined8 FUN_00102901(void)

{
  int iVar1;
  undefined8 uVar2;
  ssize_t sVar3;
  long lVar4;
  undefined8 *puVar5;
  long in_FS_OFFSET;
  byte bVar6;
  char *local_1028;
  char local_1018 [16];
  undefined8 local_1008 [511];
  long local_10;
  
  bVar6 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = open("/proc/self/status",0);
  if (iVar1 == -1) {
    uVar2 = 0;
  }
  else {
    local_1018[0] = '\0';
    local_1018[1] = '\0';
    local_1018[2] = '\0';
    local_1018[3] = '\0';
    local_1018[4] = '\0';
    local_1018[5] = '\0';
    local_1018[6] = '\0';
    local_1018[7] = '\0';
    local_1018[8] = '\0';
    local_1018[9] = '\0';
    local_1018[10] = '\0';
    local_1018[0xb] = '\0';
    local_1018[0xc] = '\0';
    local_1018[0xd] = '\0';
    local_1018[0xe] = '\0';
    local_1018[0xf] = '\0';
    puVar5 = local_1008;
    for (lVar4 = 0x1fe; lVar4 != 0; lVar4 = lVar4 + -1) {
      *puVar5 = 0;
      puVar5 = puVar5 + (ulong)bVar6 * -2 + 1;
    }
    sVar3 = read(iVar1,local_1018,0xfff);
    close(iVar1);
    if (sVar3 < 1) {
      uVar2 = 0;
    }
    else {
      local_1028 = strstr(local_1018,"TracerPid:");
      if (local_1028 != (char *)0x0) {
        for (local_1028 = local_1028 + 10; (*local_1028 == '\t' || (*local_1028 == ' '));
            local_1028 = local_1028 + 1) {
        }
        iVar1 = atoi(local_1028);
        if (iVar1 != 0) {
          uVar2 = 1;
          goto LAB_00102a4d;
        }
      }
      uVar2 = 0;
    }
  }
LAB_00102a4d:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}



//==================================================
// Function: FUN_00102a63 at 00102a63
//==================================================

bool FUN_00102a63(void)

{
  long in_FS_OFFSET;
  int local_44;
  timespec local_38;
  timespec local_28;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  clock_gettime(1,&local_38);
  for (local_44 = 0; local_44 < 100000; local_44 = local_44 + 1) {
  }
  clock_gettime(1,&local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 100000 < (local_28.tv_nsec - local_38.tv_nsec) / 1000 +
                  (local_28.tv_sec - local_38.tv_sec) * 1000000;
}



//==================================================
// Function: FUN_00102b3c at 00102b3c
//==================================================

undefined8 FUN_00102b3c(void)

{
  uint uVar1;
  int __fd;
  undefined8 uVar2;
  ssize_t sVar3;
  char *pcVar4;
  long in_FS_OFFSET;
  int local_2a0;
  char *local_288 [4];
  char *local_268;
  undefined *local_260;
  undefined *local_258;
  char *local_250;
  char *local_248;
  char *local_240;
  char *local_238;
  undefined *local_230;
  undefined8 local_228;
  char local_218 [256];
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_118[0] = '\0';
  local_118[1] = '\0';
  local_118[2] = '\0';
  local_118[3] = '\0';
  local_118[4] = '\0';
  local_118[5] = '\0';
  local_118[6] = '\0';
  local_118[7] = '\0';
  local_118[8] = '\0';
  local_118[9] = '\0';
  local_118[10] = '\0';
  local_118[0xb] = '\0';
  local_118[0xc] = '\0';
  local_118[0xd] = '\0';
  local_118[0xe] = '\0';
  local_118[0xf] = '\0';
  local_118[0x10] = '\0';
  local_118[0x11] = '\0';
  local_118[0x12] = '\0';
  local_118[0x13] = '\0';
  local_118[0x14] = '\0';
  local_118[0x15] = '\0';
  local_118[0x16] = '\0';
  local_118[0x17] = '\0';
  local_118[0x18] = '\0';
  local_118[0x19] = '\0';
  local_118[0x1a] = '\0';
  local_118[0x1b] = '\0';
  local_118[0x1c] = '\0';
  local_118[0x1d] = '\0';
  local_118[0x1e] = '\0';
  local_118[0x1f] = '\0';
  local_118[0x20] = '\0';
  local_118[0x21] = '\0';
  local_118[0x22] = '\0';
  local_118[0x23] = '\0';
  local_118[0x24] = '\0';
  local_118[0x25] = '\0';
  local_118[0x26] = '\0';
  local_118[0x27] = '\0';
  local_118[0x28] = '\0';
  local_118[0x29] = '\0';
  local_118[0x2a] = '\0';
  local_118[0x2b] = '\0';
  local_118[0x2c] = '\0';
  local_118[0x2d] = '\0';
  local_118[0x2e] = '\0';
  local_118[0x2f] = '\0';
  local_118[0x30] = '\0';
  local_118[0x31] = '\0';
  local_118[0x32] = '\0';
  local_118[0x33] = '\0';
  local_118[0x34] = '\0';
  local_118[0x35] = '\0';
  local_118[0x36] = '\0';
  local_118[0x37] = '\0';
  local_118[0x38] = '\0';
  local_118[0x39] = '\0';
  local_118[0x3a] = '\0';
  local_118[0x3b] = '\0';
  local_118[0x3c] = '\0';
  local_118[0x3d] = '\0';
  local_118[0x3e] = '\0';
  local_118[0x3f] = '\0';
  local_118[0x40] = '\0';
  local_118[0x41] = '\0';
  local_118[0x42] = '\0';
  local_118[0x43] = '\0';
  local_118[0x44] = '\0';
  local_118[0x45] = '\0';
  local_118[0x46] = '\0';
  local_118[0x47] = '\0';
  local_118[0x48] = '\0';
  local_118[0x49] = '\0';
  local_118[0x4a] = '\0';
  local_118[0x4b] = '\0';
  local_118[0x4c] = '\0';
  local_118[0x4d] = '\0';
  local_118[0x4e] = '\0';
  local_118[0x4f] = '\0';
  local_118[0x50] = '\0';
  local_118[0x51] = '\0';
  local_118[0x52] = '\0';
  local_118[0x53] = '\0';
  local_118[0x54] = '\0';
  local_118[0x55] = '\0';
  local_118[0x56] = '\0';
  local_118[0x57] = '\0';
  local_118[0x58] = '\0';
  local_118[0x59] = '\0';
  local_118[0x5a] = '\0';
  local_118[0x5b] = '\0';
  local_118[0x5c] = '\0';
  local_118[0x5d] = '\0';
  local_118[0x5e] = '\0';
  local_118[0x5f] = '\0';
  local_118[0x60] = '\0';
  local_118[0x61] = '\0';
  local_118[0x62] = '\0';
  local_118[99] = '\0';
  local_118[100] = '\0';
  local_118[0x65] = '\0';
  local_118[0x66] = '\0';
  local_118[0x67] = '\0';
  local_118[0x68] = '\0';
  local_118[0x69] = '\0';
  local_118[0x6a] = '\0';
  local_118[0x6b] = '\0';
  local_118[0x6c] = '\0';
  local_118[0x6d] = '\0';
  local_118[0x6e] = '\0';
  local_118[0x6f] = '\0';
  local_118[0x70] = '\0';
  local_118[0x71] = '\0';
  local_118[0x72] = '\0';
  local_118[0x73] = '\0';
  local_118[0x74] = '\0';
  local_118[0x75] = '\0';
  local_118[0x76] = '\0';
  local_118[0x77] = '\0';
  local_118[0x78] = '\0';
  local_118[0x79] = '\0';
  local_118[0x7a] = '\0';
  local_118[0x7b] = '\0';
  local_118[0x7c] = '\0';
  local_118[0x7d] = '\0';
  local_118[0x7e] = '\0';
  local_118[0x7f] = '\0';
  local_118[0x80] = '\0';
  local_118[0x81] = '\0';
  local_118[0x82] = '\0';
  local_118[0x83] = '\0';
  local_118[0x84] = '\0';
  local_118[0x85] = '\0';
  local_118[0x86] = '\0';
  local_118[0x87] = '\0';
  local_118[0x88] = '\0';
  local_118[0x89] = '\0';
  local_118[0x8a] = '\0';
  local_118[0x8b] = '\0';
  local_118[0x8c] = '\0';
  local_118[0x8d] = '\0';
  local_118[0x8e] = '\0';
  local_118[0x8f] = '\0';
  local_118[0x90] = '\0';
  local_118[0x91] = '\0';
  local_118[0x92] = '\0';
  local_118[0x93] = '\0';
  local_118[0x94] = '\0';
  local_118[0x95] = '\0';
  local_118[0x96] = '\0';
  local_118[0x97] = '\0';
  local_118[0x98] = '\0';
  local_118[0x99] = '\0';
  local_118[0x9a] = '\0';
  local_118[0x9b] = '\0';
  local_118[0x9c] = '\0';
  local_118[0x9d] = '\0';
  local_118[0x9e] = '\0';
  local_118[0x9f] = '\0';
  local_118[0xa0] = '\0';
  local_118[0xa1] = '\0';
  local_118[0xa2] = '\0';
  local_118[0xa3] = '\0';
  local_118[0xa4] = '\0';
  local_118[0xa5] = '\0';
  local_118[0xa6] = '\0';
  local_118[0xa7] = '\0';
  local_118[0xa8] = '\0';
  local_118[0xa9] = '\0';
  local_118[0xaa] = '\0';
  local_118[0xab] = '\0';
  local_118[0xac] = '\0';
  local_118[0xad] = '\0';
  local_118[0xae] = '\0';
  local_118[0xaf] = '\0';
  local_118[0xb0] = '\0';
  local_118[0xb1] = '\0';
  local_118[0xb2] = '\0';
  local_118[0xb3] = '\0';
  local_118[0xb4] = '\0';
  local_118[0xb5] = '\0';
  local_118[0xb6] = '\0';
  local_118[0xb7] = '\0';
  local_118[0xb8] = '\0';
  local_118[0xb9] = '\0';
  local_118[0xba] = '\0';
  local_118[0xbb] = '\0';
  local_118[0xbc] = '\0';
  local_118[0xbd] = '\0';
  local_118[0xbe] = '\0';
  local_118[0xbf] = '\0';
  local_118[0xc0] = '\0';
  local_118[0xc1] = '\0';
  local_118[0xc2] = '\0';
  local_118[0xc3] = '\0';
  local_118[0xc4] = '\0';
  local_118[0xc5] = '\0';
  local_118[0xc6] = '\0';
  local_118[199] = '\0';
  local_118[200] = '\0';
  local_118[0xc9] = '\0';
  local_118[0xca] = '\0';
  local_118[0xcb] = '\0';
  local_118[0xcc] = '\0';
  local_118[0xcd] = '\0';
  local_118[0xce] = '\0';
  local_118[0xcf] = '\0';
  local_118[0xd0] = '\0';
  local_118[0xd1] = '\0';
  local_118[0xd2] = '\0';
  local_118[0xd3] = '\0';
  local_118[0xd4] = '\0';
  local_118[0xd5] = '\0';
  local_118[0xd6] = '\0';
  local_118[0xd7] = '\0';
  local_118[0xd8] = '\0';
  local_118[0xd9] = '\0';
  local_118[0xda] = '\0';
  local_118[0xdb] = '\0';
  local_118[0xdc] = '\0';
  local_118[0xdd] = '\0';
  local_118[0xde] = '\0';
  local_118[0xdf] = '\0';
  local_118[0xe0] = '\0';
  local_118[0xe1] = '\0';
  local_118[0xe2] = '\0';
  local_118[0xe3] = '\0';
  local_118[0xe4] = '\0';
  local_118[0xe5] = '\0';
  local_118[0xe6] = '\0';
  local_118[0xe7] = '\0';
  local_118[0xe8] = '\0';
  local_118[0xe9] = '\0';
  local_118[0xea] = '\0';
  local_118[0xeb] = '\0';
  local_118[0xec] = '\0';
  local_118[0xed] = '\0';
  local_118[0xee] = '\0';
  local_118[0xef] = '\0';
  local_118[0xf0] = '\0';
  local_118[0xf1] = '\0';
  local_118[0xf2] = '\0';
  local_118[0xf3] = '\0';
  local_118[0xf4] = '\0';
  local_118[0xf5] = '\0';
  local_118[0xf6] = '\0';
  local_118[0xf7] = '\0';
  local_118[0xf8] = '\0';
  local_118[0xf9] = '\0';
  local_118[0xfa] = '\0';
  local_118[0xfb] = '\0';
  local_118[0xfc] = '\0';
  local_118[0xfd] = '\0';
  local_118[0xfe] = '\0';
  local_118[0xff] = '\0';
  uVar1 = getppid();
  snprintf(local_218,0x100,"/proc/%d/comm",(ulong)uVar1);
  __fd = open(local_218,0);
  if (__fd == -1) {
    uVar2 = 0;
  }
  else {
    sVar3 = read(__fd,local_118,0xff);
    close(__fd);
    if (sVar3 < 1) {
      uVar2 = 0;
    }
    else {
      pcVar4 = strchr(local_118,10);
      if (pcVar4 != (char *)0x0) {
        *pcVar4 = '\0';
      }
      local_288[0] = "gdb";
      local_288[1] = "lldb";
      local_288[2] = "strace";
      local_288[3] = "ltrace";
      local_268 = "radare2";
      local_260 = &DAT_00108080;
      local_258 = &DAT_00108083;
      local_250 = "ida64";
      local_248 = "x64dbg";
      local_240 = "ollydbg";
      local_238 = "windbg";
      local_230 = &DAT_001080a3;
      local_228 = 0;
      for (local_2a0 = 0; local_288[local_2a0] != (char *)0x0; local_2a0 = local_2a0 + 1) {
        pcVar4 = strstr(local_118,local_288[local_2a0]);
        if (pcVar4 != (char *)0x0) {
          uVar2 = 1;
          goto LAB_00102e6c;
        }
      }
      uVar2 = 0;
    }
  }
LAB_00102e6c:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}



//==================================================
// Function: FUN_00102e82 at 00102e82
//==================================================

bool FUN_00102e82(void)

{
  char cVar1;
  char cVar2;
  bool local_9;
  
  DAT_0010c290 = 0;
  cVar1 = FUN_00102894();
  if (cVar1 != '\x01') {
    DAT_0010c290 = DAT_0010c290 | 0xa623000000000000;
  }
  cVar2 = FUN_00102901();
  if (cVar2 != '\x01') {
    DAT_0010c290 = DAT_0010c290 | 0x73a700000000;
  }
  local_9 = cVar2 == '\x01' || cVar1 == '\x01';
  cVar1 = FUN_00102a63();
  if (cVar1 == '\x01') {
    local_9 = true;
  }
  else {
    DAT_0010c290 = DAT_0010c290 | 0x70290000;
  }
  cVar1 = FUN_00102b3c();
  if (cVar1 == '\x01') {
    local_9 = true;
  }
  else {
    DAT_0010c290 = DAT_0010c290 | 0x31c7;
  }
  return local_9;
}



//==================================================
// Function: FUN_00102f49 at 00102f49
//==================================================

undefined8 FUN_00102f49(void)

{
  return DAT_0010c290;
}



//==================================================
// Function: _INIT_1 at 00102f5a
//==================================================

void _INIT_1(void)

{
  FUN_001033c9();
  return;
}



//==================================================
// Function: FUN_00102f79 at 00102f79
//==================================================

void FUN_00102f79(void)

{
  puts("Welcome my DRM-protected application!");
  puts("To sucessfully get in, you must present a valid license file.");
  puts("Reverse engineer this binary to figure out the license format, and get the flag. :)");
  puts("Good luck!\n");
  puts("Usage: ./challenge <license file path>");
  return;
}



//==================================================
// Function: FUN_00102fcf at 00102fcf
//==================================================

undefined8 FUN_00102fcf(int param_1,long param_2)

{
  code *pcVar1;
  char cVar2;
  int iVar3;
  long in_FS_OFFSET;
  undefined1 local_5c [4];
  ulong local_58;
  ulong local_50;
  undefined8 local_48;
  char *local_40;
  char *local_38;
  undefined8 local_30;
  char *local_28;
  ulong local_20;
  void *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 < 2) {
    FUN_00102f79();
  }
  else {
    local_48 = *(undefined8 *)(param_2 + 8);
    local_40 = (char *)FUN_00103471(local_48);
    puts("[i] loaded license file");
    local_38 = "LICENSE-";
    local_30 = 8;
    if (local_40 != (char *)0x0) {
      iVar3 = strncmp(local_40,"LICENSE-",8);
      if (iVar3 == 0) {
        local_28 = local_40 + 8;
        for (local_58 = strlen(local_28);
            (local_58 != 0 &&
            (((local_28[local_58 - 1] == '\n' || (local_28[local_58 - 1] == '\r')) ||
             (local_28[local_58 - 1] == ' ')))); local_58 = local_58 - 1) {
        }
        local_20 = local_58 >> 1;
        local_18 = calloc(1,local_20 + 1);
        for (local_50 = 0; local_50 < local_20; local_50 = local_50 + 1) {
          __isoc99_sscanf(local_28 + local_50 * 2,&DAT_001081e3,local_5c);
          *(char *)(local_50 + (long)local_18) = local_5c[0];
        }
        FUN_00103589(local_18,local_20);
        free(local_18);
        cVar2 = FUN_00102e82();
        if (cVar2 == '\0') {
                    /* WARNING: Does not return */
          pcVar1 = (code *)invalidInstructionException();
          (*pcVar1)();
        }
        puts("DEBUGGER DETECTED! LICENSING TERMS VIOLATED! >:(");
        puts("exiting...");
        free(local_40);
        goto LAB_001031e9;
      }
    }
    puts("[!] invalid license format");
    free(local_40);
  }
LAB_001031e9:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0xffffffff;
}



//==================================================
// Function: FUN_001031ff at 001031ff
//==================================================

undefined * FUN_001031ff(void)

{
  ulong uVar1;
  int local_c;
  
  for (local_c = 0; local_c < 0x20; local_c = local_c + 1) {
    uVar1 = FUN_00102f49();
    (&DAT_0010c2a0)[local_c] = (char)(uVar1 >> ((byte)(local_c << 3) & 0x3f));
  }
  return &DAT_0010c2a0;
}



//==================================================
// Function: FUN_00103248 at 00103248
//==================================================

void FUN_00103248(void)

{
  undefined8 uVar1;
  long lVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  long in_FS_OFFSET;
  undefined1 local_e8 [192];
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (DAT_0010c2c0 == '\0') {
    DAT_0010d2e0 = 0x3a0;
    DAT_0010c2e0 = DAT_0010bb00;
    DAT_0010c678 = DAT_0010be98;
    puVar3 = &DAT_0010bb08;
    puVar4 = &DAT_0010c2e8;
    for (lVar2 = 0x73; lVar2 != 0; lVar2 = lVar2 + -1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + 1;
      puVar4 = puVar4 + 1;
    }
    local_28 = 0;
    local_20 = 0;
    uVar1 = FUN_001031ff();
    FUN_00106843(local_e8,uVar1,&local_28);
    FUN_00107837(local_e8,&DAT_0010c2e0,DAT_0010d2e0);
    DAT_0010c2c0 = '\x01';
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: FUN_0010334f at 0010334f
//==================================================

undefined8 * FUN_0010334f(undefined8 *param_1)

{
  if (param_1 != (undefined8 *)0x0) {
    *param_1 = DAT_0010d2e0;
  }
  return &DAT_0010c2e0;
}



//==================================================
// Function: FUN_00103379 at 00103379
//==================================================

void FUN_00103379(undefined8 param_1,undefined8 param_2,long param_3)

{
  FUN_00103248();
  puts("processing... please wait...");
  *(long *)(param_3 + 0xa8) = *(long *)(param_3 + 0xa8) + 2;
  return;
}



//==================================================
// Function: FUN_001033c9 at 001033c9
//==================================================

void FUN_001033c9(void)

{
  int iVar1;
  long in_FS_OFFSET;
  sigaction local_a8;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  memset(&local_a8,0,0x98);
  local_a8.__sigaction_handler.sa_handler = FUN_00103379;
  local_a8.sa_flags = 0x10000004;
  sigemptyset(&local_a8.sa_mask);
  iVar1 = sigaction(4,&local_a8,(sigaction *)0x0);
  if (iVar1 == -1) {
    perror("sigaction");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: FUN_00103471 at 00103471
//==================================================

void * FUN_00103471(char *param_1)

{
  FILE *__stream;
  void *__ptr;
  size_t __n;
  
  __stream = fopen(param_1,"rb");
  if (__stream == (FILE *)0x0) {
    __ptr = (void *)0x0;
  }
  else {
    fseek(__stream,0,2);
    __n = ftell(__stream);
    fseek(__stream,0,0);
    __ptr = calloc(1,__n + 1);
    fread(__ptr,1,__n,__stream);
    *(undefined1 *)((long)__ptr + __n) = 0;
    fclose(__stream);
  }
  return __ptr;
}



//==================================================
// Function: FUN_0010353a at 0010353a
//==================================================

bool FUN_0010353a(char *param_1)

{
  int iVar1;
  size_t __n;
  
  __n = strlen("MYVERYREALLDRM");
  iVar1 = strncmp("MYVERYREALLDRM",param_1,__n);
  return iVar1 == 0;
}



//==================================================
// Function: FUN_00103589 at 00103589
//==================================================

void FUN_00103589(void *param_1,size_t param_2)

{
  if (DAT_0010d2f0 != (void *)0x0) {
    free(DAT_0010d2f0);
  }
  DAT_0010d2f0 = malloc(param_2);
  if (DAT_0010d2f0 != (void *)0x0) {
    memcpy(DAT_0010d2f0,param_1,param_2);
    DAT_0010d2f8 = param_2;
  }
  return;
}



//==================================================
// Function: FUN_001035ff at 001035ff
//==================================================

void FUN_001035ff(long param_1)

{
  byte bVar1;
  byte bVar2;
  uint uVar3;
  char *pcVar4;
  
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  uVar3 = *(uint *)(param_1 + 0xa4);
  *(uint *)(param_1 + 0xa4) = uVar3 + 1;
  bVar1 = *(byte *)((ulong)uVar3 + *(long *)(param_1 + 0xa8));
  uVar3 = *(uint *)(param_1 + 0xa4);
  *(uint *)(param_1 + 0xa4) = uVar3 + 1;
  bVar2 = *(byte *)((ulong)uVar3 + *(long *)(param_1 + 0xa8));
  if ((bVar1 < 10) && (bVar2 < 10)) {
    uVar3 = *(uint *)((long)(int)(uint)bVar2 * 0x10 + param_1);
    if ((DAT_0010d2f0 == 0) || (DAT_0010d2f8 <= uVar3)) {
      pcVar4 = getenv("DEBUG");
      if (pcVar4 != (char *)0x0) {
        printf("GET_LICENSE_BYTE[%u] -> 0 (OOB/NULL)\n",(ulong)uVar3);
      }
      *(undefined4 *)((long)(int)(uint)bVar1 * 0x10 + param_1) = 0;
    }
    else {
      *(uint *)((long)(int)(uint)bVar1 * 0x10 + param_1) =
           (uint)*(byte *)((ulong)uVar3 + DAT_0010d2f0);
    }
    *(undefined4 *)((long)(int)(uint)bVar1 * 0x10 + param_1 + 8) = 0;
  }
  else {
    fwrite("GET_LICENSE_BYTE: register out of bounds\n",1,0x29,stderr);
    *(undefined2 *)(param_1 + 0x18c4) = 0;
  }
  return;
}



//==================================================
// Function: FUN_00103781 at 00103781
//==================================================

void FUN_00103781(long param_1)

{
  byte bVar1;
  uint uVar2;
  char *pcVar3;
  
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  uVar2 = *(uint *)(param_1 + 0xa4);
  *(uint *)(param_1 + 0xa4) = uVar2 + 1;
  bVar1 = *(byte *)((ulong)uVar2 + *(long *)(param_1 + 0xa8));
  pcVar3 = getenv("PRINT_FLAG_CHAR");
  if (pcVar3 != (char *)0x0) {
    if (bVar1 < 10) {
      putchar(*(int *)((long)(int)(uint)bVar1 * 0x10 + param_1));
      fflush(stdout);
    }
    else {
      fwrite("PRINT_CHAR: register out of bounds\nContact the challenge author.",1,0x40,stderr);
      *(undefined2 *)(param_1 + 0x18c4) = 0;
    }
  }
  return;
}



//==================================================
// Function: FUN_00103851 at 00103851
//==================================================

undefined8 FUN_00103851(void)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = FUN_0010399d(PTR_DAT_0010c248,DAT_0010d2e0 & 0xffffffff);
  if (lVar1 == 0) {
    puts("[!] failed to create virtual machine instance.");
    uVar2 = 0xffffffff;
  }
  else {
    *(code **)(lVar1 + 0x4d0) = FUN_001035ff;
    *(code **)(lVar1 + 0x4e0) = FUN_00103781;
    puts("[i] running program...");
    FUN_00103cdf(lVar1);
    FUN_00103c85(lVar1);
    uVar2 = 0;
  }
  return uVar2;
}



//==================================================
// Function: FUN_001038ee at 001038ee
//==================================================

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_001038ee(int param_1,int param_2)

{
  if ((param_1 == 1) && (param_2 == 0xffff)) {
    _DAT_0010d2e8 = DAT_0010d2e0;
  }
  return;
}



//==================================================
// Function: _INIT_2 at 0010391c
//==================================================

void _INIT_2(void)

{
  FUN_001038ee(1,0xffff);
  return;
}



//==================================================
// Function: FUN_00103935 at 00103935
//==================================================

void FUN_00103935(long param_1,undefined8 param_2)

{
  if (*(long *)(param_1 + 0xb8) != 0) {
    (**(code **)(param_1 + 0xb8))(param_2);
    return;
  }
  fprintf(stderr,"%s\n",param_2);
                    /* WARNING: Subroutine does not return */
  exit(1);
}



//==================================================
// Function: FUN_0010399d at 0010399d
//==================================================

void * FUN_0010399d(void *param_1,uint param_2)

{
  void *__s;
  void *pvVar1;
  int local_14;
  
  if (((param_1 == (void *)0x0) || (param_2 == 0)) || (0xffff < param_2)) {
    __s = (void *)0x0;
  }
  else {
    __s = malloc(0x18c8);
    if (__s == (void *)0x0) {
      __s = (void *)0x0;
    }
    else {
      memset(__s,0,0x18c8);
      pvVar1 = malloc(0xffff);
      *(void **)((long)__s + 0xa8) = pvVar1;
      if (*(long *)((long)__s + 0xa8) == 0) {
        free(__s);
        __s = (void *)0x0;
      }
      else {
        *(undefined8 *)((long)__s + 0xb8) = 0;
        *(undefined4 *)((long)__s + 0xa4) = 0;
        *(undefined2 *)((long)__s + 0x18c4) = 1;
        *(uint *)((long)__s + 0xb0) = param_2;
        memset(*(void **)((long)__s + 0xa8),0,0xffff);
        memcpy(*(void **)((long)__s + 0xa8),param_1,(ulong)param_2);
        for (local_14 = 0; local_14 < 10; local_14 = local_14 + 1) {
          *(undefined4 *)((long)__s + (long)local_14 * 0x10 + 8) = 0;
          *(undefined4 *)((long)local_14 * 0x10 + (long)__s) = 0;
          *(undefined8 *)((long)local_14 * 0x10 + (long)__s) = 0;
        }
        *(undefined2 *)((long)__s + 0xa0) = 0;
        *(undefined4 *)((long)__s + 0x18c0) = 0;
        FUN_0010627f(__s);
      }
    }
  }
  return __s;
}



//==================================================
// Function: FUN_00103b3b at 00103b3b
//==================================================

void FUN_00103b3b(long param_1,undefined8 param_2)

{
  *(undefined8 *)(param_1 + 0xb8) = param_2;
  return;
}



//==================================================
// Function: FUN_00103b5d at 00103b5d
//==================================================

void FUN_00103b5d(long param_1)

{
  uint local_c;
  
  puts("Register dump");
  for (local_c = 0; (int)local_c < 10; local_c = local_c + 1) {
    if (*(int *)((long)(int)local_c * 0x10 + param_1 + 8) == 1) {
      printf("\tRegister %02d - str: %s\n",(ulong)local_c,
             *(undefined8 *)((long)(int)local_c * 0x10 + param_1));
    }
    else if (*(int *)((long)(int)local_c * 0x10 + param_1 + 8) == 0) {
      printf("\tRegister %02d - Decimal:%04d [Hex:%04X]\n",(ulong)local_c,
             (ulong)*(uint *)((long)(int)local_c * 0x10 + param_1),
             (ulong)*(uint *)((long)(int)local_c * 0x10 + param_1));
    }
    else {
      printf("\tRegister %02d has unknown type!\n",(ulong)local_c);
    }
  }
  if (*(short *)(param_1 + 0xa0) == 1) {
    puts("\tZ-FLAG:true");
  }
  else {
    puts("\tZ-FLAG:false");
  }
  return;
}



//==================================================
// Function: FUN_00103c85 at 00103c85
//==================================================

void FUN_00103c85(void *param_1)

{
  if (param_1 != (void *)0x0) {
    if (*(long *)((long)param_1 + 0xa8) != 0) {
      free(*(void **)((long)param_1 + 0xa8));
      *(undefined8 *)((long)param_1 + 0xa8) = 0;
    }
    free(param_1);
  }
  return;
}



//==================================================
// Function: FUN_00103cdf at 00103cdf
//==================================================

void FUN_00103cdf(undefined8 param_1)

{
  FUN_00103d03(param_1,0);
  return;
}



//==================================================
// Function: FUN_00103d03 at 00103d03
//==================================================

void FUN_00103d03(long param_1,int param_2)

{
  uint uVar1;
  int local_10;
  
  local_10 = 0;
  if (param_1 != 0) {
    *(undefined4 *)(param_1 + 0xa4) = 0;
    while (*(short *)(param_1 + 0x18c4) == 1) {
      if (0xfffe < *(uint *)(param_1 + 0xa4)) {
        *(undefined4 *)(param_1 + 0xa4) = 0;
      }
      uVar1 = (uint)*(byte *)((ulong)*(uint *)(param_1 + 0xa4) + *(long *)(param_1 + 0xa8));
      if (*(long *)(param_1 + ((long)(int)uVar1 + 0x18) * 8) != 0) {
        (**(code **)(param_1 + ((long)(int)uVar1 + 0x18) * 8))(param_1);
      }
      local_10 = local_10 + 1;
      if ((param_2 != 0) && (param_2 <= local_10)) {
        *(undefined2 *)(param_1 + 0x18c4) = 0;
      }
    }
  }
  return;
}



//==================================================
// Function: FUN_00103de8 at 00103de8
//==================================================

undefined8 FUN_00103de8(long param_1,int param_2)

{
  undefined8 uVar1;
  
  if (*(int *)((long)param_2 * 0x10 + param_1 + 8) == 1) {
    uVar1 = *(undefined8 *)((long)param_2 * 0x10 + param_1);
  }
  else {
    FUN_00103935(param_1,"The register deesn\'t contain a string");
    uVar1 = 0;
  }
  return uVar1;
}



//==================================================
// Function: FUN_00103e48 at 00103e48
//==================================================

undefined4 FUN_00103e48(long param_1,int param_2)

{
  undefined4 uVar1;
  
  if (*(int *)((long)param_2 * 0x10 + param_1 + 8) == 0) {
    uVar1 = *(undefined4 *)((long)param_2 * 0x10 + param_1);
  }
  else {
    FUN_00103935(param_1,"The register doesn\'t contain an integer");
    uVar1 = 0;
  }
  return uVar1;
}



//==================================================
// Function: FUN_00103ea6 at 00103ea6
//==================================================

void * FUN_00103ea6(long param_1)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  void *__s;
  int local_20;
  
  bVar1 = FUN_00103fe0(param_1);
  bVar2 = FUN_00103fe0(param_1);
  iVar3 = (uint)bVar1 + (uint)bVar2 * 0x100;
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  __s = malloc((long)(iVar3 + 1));
  if (__s == (void *)0x0) {
    FUN_00103935(param_1,"RAM allocation failure.");
  }
  memset(__s,0,(long)(iVar3 + 1));
  for (local_20 = 0; local_20 < iVar3; local_20 = local_20 + 1) {
    if (0xfffe < *(uint *)(param_1 + 0xa4)) {
      *(undefined4 *)(param_1 + 0xa4) = 0;
    }
    *(undefined1 *)((long)__s + (long)local_20) =
         *(undefined1 *)((ulong)*(uint *)(param_1 + 0xa4) + *(long *)(param_1 + 0xa8));
    *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + -1;
  return __s;
}



//==================================================
// Function: FUN_00103fe0 at 00103fe0
//==================================================

undefined1 FUN_00103fe0(long param_1)

{
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  if (0xfffe < *(uint *)(param_1 + 0xa4)) {
    *(undefined4 *)(param_1 + 0xa4) = 0;
  }
  return *(undefined1 *)((ulong)*(uint *)(param_1 + 0xa4) + *(long *)(param_1 + 0xa8));
}



//==================================================
// Function: FUN_00104041 at 00104041
//==================================================

void FUN_00104041(long param_1)

{
  printf("%04X - op_unknown(%02X)\n",(ulong)*(uint *)(param_1 + 0xa4),
         (ulong)*(byte *)((ulong)*(uint *)(param_1 + 0xa4) + *(long *)(param_1 + 0xa8)));
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_001040b1 at 001040b1
//==================================================

void FUN_001040b1(long param_1)

{
  *(undefined2 *)(param_1 + 0x18c4) = 0;
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_001040e4 at 001040e4
//==================================================

void FUN_001040e4(long param_1)

{
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_0010410a at 0010410a
//==================================================

void FUN_0010410a(long param_1)

{
  byte bVar1;
  undefined1 uVar2;
  undefined1 uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar4 = (uint)bVar1;
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar2 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar3 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if ((*(int *)((ulong)uVar4 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar4 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar4 * 0x10 + param_1));
  }
  iVar5 = FUN_00103e48(param_1,uVar2);
  iVar6 = FUN_00103e48(param_1,uVar3);
  if (iVar6 == 0) {
    FUN_00103935(param_1,"Division by zero!");
  }
  else {
    *(int *)((ulong)uVar4 * 0x10 + param_1) = iVar5 / iVar6;
    *(undefined4 *)((ulong)uVar4 * 0x10 + param_1 + 8) = 0;
    if (*(int *)((ulong)uVar4 * 0x10 + param_1) == 0) {
      *(undefined2 *)(param_1 + 0xa0) = 1;
    }
    else {
      *(undefined2 *)(param_1 + 0xa0) = 0;
    }
    *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  }
  return;
}



//==================================================
// Function: FUN_001042ac at 001042ac
//==================================================

void FUN_001042ac(long param_1)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  char *pcVar4;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar2 = (uint)bVar1;
  if (9 < uVar2) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  bVar1 = FUN_00103fe0(param_1);
  uVar3 = (uint)bVar1;
  if (9 < uVar3) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if ((*(int *)((ulong)uVar2 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar2 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar2 * 0x10 + param_1));
  }
  if (*(int *)((ulong)uVar3 * 0x10 + param_1 + 8) == 1) {
    *(undefined4 *)((ulong)uVar2 * 0x10 + param_1 + 8) = 1;
    pcVar4 = strdup(*(char **)((ulong)uVar3 * 0x10 + param_1));
    *(char **)((ulong)uVar2 * 0x10 + param_1) = pcVar4;
  }
  else {
    *(undefined4 *)((ulong)uVar2 * 0x10 + param_1 + 8) =
         *(undefined4 *)((ulong)uVar3 * 0x10 + param_1 + 8);
    *(undefined4 *)((ulong)uVar2 * 0x10 + param_1) = *(undefined4 *)((ulong)uVar3 * 0x10 + param_1);
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00104422 at 00104422
//==================================================

void FUN_00104422(long param_1)

{
  byte bVar1;
  byte bVar2;
  uint uVar3;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar3 = (uint)bVar1;
  if (9 < uVar3) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  bVar1 = FUN_00103fe0(param_1);
  bVar2 = FUN_00103fe0(param_1);
  if ((*(int *)((ulong)uVar3 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar3 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar3 * 0x10 + param_1));
  }
  *(uint *)((ulong)uVar3 * 0x10 + param_1) = (uint)bVar1 + (uint)bVar2 * 0x100;
  *(undefined4 *)((ulong)uVar3 * 0x10 + param_1 + 8) = 0;
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00104521 at 00104521
//==================================================

void FUN_00104521(long param_1)

{
  byte bVar1;
  uint uVar2;
  
  bVar1 = FUN_00103fe0(param_1);
  if (9 < bVar1) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar2 = FUN_00103e48(param_1,bVar1);
  printf("0x%04X",(ulong)uVar2);
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_001045a6 at 001045a6
//==================================================

void FUN_001045a6(long param_1)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  void *pvVar4;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar2 = (uint)bVar1;
  if (9 < uVar2) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar3 = FUN_00103e48(param_1,uVar2);
  *(undefined4 *)((ulong)uVar2 * 0x10 + param_1 + 8) = 1;
  pvVar4 = malloc(10);
  *(void **)((ulong)uVar2 * 0x10 + param_1) = pvVar4;
  memset(*(void **)((ulong)uVar2 * 0x10 + param_1),0,10);
  sprintf(*(char **)((ulong)uVar2 * 0x10 + param_1),"%d",(ulong)uVar3);
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00104696 at 00104696
//==================================================

void FUN_00104696(long param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar2 = (uint)bVar1;
  if (9 < uVar2) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if ((*(int *)((ulong)uVar2 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar2 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar2 * 0x10 + param_1));
  }
  *(undefined4 *)((ulong)uVar2 * 0x10 + param_1 + 8) = 0;
  iVar3 = rand();
  *(int *)((ulong)uVar2 * 0x10 + param_1) = iVar3 % 0xffff;
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00104788 at 00104788
//==================================================

void FUN_00104788(long param_1)

{
  byte bVar1;
  uint uVar2;
  undefined8 uVar3;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar2 = (uint)bVar1;
  if (9 < uVar2) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar3 = FUN_00103ea6(param_1);
  if ((*(int *)((ulong)uVar2 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar2 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar2 * 0x10 + param_1));
  }
  *(undefined4 *)((ulong)uVar2 * 0x10 + param_1 + 8) = 1;
  *(undefined8 *)(param_1 + (ulong)uVar2 * 0x10) = uVar3;
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00104865 at 00104865
//==================================================

void FUN_00104865(long param_1)

{
  byte bVar1;
  undefined8 uVar2;
  
  bVar1 = FUN_00103fe0(param_1);
  if (9 < bVar1) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar2 = FUN_00103de8(param_1,bVar1);
  printf("%s",uVar2);
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_001048ed at 001048ed
//==================================================

void FUN_001048ed(long param_1)

{
  byte bVar1;
  undefined1 uVar2;
  undefined1 uVar3;
  uint uVar4;
  int iVar5;
  char *__s;
  char *__s_00;
  size_t sVar6;
  size_t sVar7;
  char *__s_01;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar4 = (uint)bVar1;
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar2 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar3 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  __s = (char *)FUN_00103de8(param_1,uVar2);
  __s_00 = (char *)FUN_00103de8(param_1,uVar3);
  sVar6 = strlen(__s);
  sVar7 = strlen(__s_00);
  iVar5 = (int)sVar7 + (int)sVar6 + 1;
  __s_01 = (char *)malloc((long)iVar5);
  memset(__s_01,0,(long)iVar5);
  sprintf(__s_01,"%s%s",__s,__s_00);
  if ((*(int *)((ulong)uVar4 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar4 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar4 * 0x10 + param_1));
  }
  *(char **)(param_1 + (ulong)uVar4 * 0x10) = __s_01;
  *(undefined4 *)((ulong)uVar4 * 0x10 + param_1 + 8) = 1;
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00104aaf at 00104aaf
//==================================================

void FUN_00104aaf(long param_1)

{
  byte bVar1;
  char *__command;
  
  bVar1 = FUN_00103fe0(param_1);
  if (9 < bVar1) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  __command = (char *)FUN_00103de8(param_1,bVar1);
  system(__command);
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00104b2b at 00104b2b
//==================================================

void FUN_00104b2b(long param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  char *__nptr;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar2 = (uint)bVar1;
  if (9 < uVar2) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  __nptr = (char *)FUN_00103de8(param_1,uVar2);
  iVar3 = atoi(__nptr);
  free(*(void **)((ulong)uVar2 * 0x10 + param_1));
  *(undefined4 *)((ulong)uVar2 * 0x10 + param_1 + 8) = 0;
  *(int *)((ulong)uVar2 * 0x10 + param_1) = iVar3;
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00104beb at 00104beb
//==================================================

void FUN_00104beb(long param_1)

{
  byte bVar1;
  byte bVar2;
  
  bVar1 = FUN_00103fe0(param_1);
  bVar2 = FUN_00103fe0(param_1);
  *(uint *)(param_1 + 0xa4) = (uint)bVar1 + (uint)bVar2 * 0x100;
  return;
}



//==================================================
// Function: FUN_00104c3f at 00104c3f
//==================================================

void FUN_00104c3f(long param_1)

{
  byte bVar1;
  byte bVar2;
  
  bVar1 = FUN_00103fe0(param_1);
  bVar2 = FUN_00103fe0(param_1);
  if (*(short *)(param_1 + 0xa0) == 0) {
    *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  }
  else {
    *(uint *)(param_1 + 0xa4) = (uint)bVar1 + (uint)bVar2 * 0x100;
  }
  return;
}



//==================================================
// Function: FUN_00104cbc at 00104cbc
//==================================================

void FUN_00104cbc(long param_1)

{
  byte bVar1;
  byte bVar2;
  
  bVar1 = FUN_00103fe0(param_1);
  bVar2 = FUN_00103fe0(param_1);
  if (*(short *)(param_1 + 0xa0) == 0) {
    *(uint *)(param_1 + 0xa4) = (uint)bVar1 + (uint)bVar2 * 0x100;
  }
  else {
    *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  }
  return;
}



//==================================================
// Function: FUN_00104d39 at 00104d39
//==================================================

void FUN_00104d39(long param_1)

{
  byte bVar1;
  undefined1 uVar2;
  undefined1 uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar4 = (uint)bVar1;
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar2 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar3 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if ((*(int *)((ulong)uVar4 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar4 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar4 * 0x10 + param_1));
  }
  iVar5 = FUN_00103e48(param_1,uVar2);
  iVar6 = FUN_00103e48(param_1,uVar3);
  *(int *)((ulong)uVar4 * 0x10 + param_1) = iVar6 + iVar5;
  *(undefined4 *)((ulong)uVar4 * 0x10 + param_1 + 8) = 0;
  if (*(int *)((ulong)uVar4 * 0x10 + param_1) == 0) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  else {
    *(undefined2 *)(param_1 + 0xa0) = 0;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00104ebe at 00104ebe
//==================================================

void FUN_00104ebe(long param_1)

{
  byte bVar1;
  undefined1 uVar2;
  undefined1 uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar4 = (uint)bVar1;
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar2 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar3 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if ((*(int *)((ulong)uVar4 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar4 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar4 * 0x10 + param_1));
  }
  uVar5 = FUN_00103e48(param_1,uVar2);
  uVar6 = FUN_00103e48(param_1,uVar3);
  *(uint *)((ulong)uVar4 * 0x10 + param_1) = uVar5 & uVar6;
  *(undefined4 *)((ulong)uVar4 * 0x10 + param_1 + 8) = 0;
  if (*(int *)((ulong)uVar4 * 0x10 + param_1) == 0) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  else {
    *(undefined2 *)(param_1 + 0xa0) = 0;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00105041 at 00105041
//==================================================

void FUN_00105041(long param_1)

{
  byte bVar1;
  undefined1 uVar2;
  undefined1 uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar4 = (uint)bVar1;
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar2 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar3 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if ((*(int *)((ulong)uVar4 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar4 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar4 * 0x10 + param_1));
  }
  iVar5 = FUN_00103e48(param_1,uVar2);
  iVar6 = FUN_00103e48(param_1,uVar3);
  *(int *)((ulong)uVar4 * 0x10 + param_1) = iVar5 - iVar6;
  *(undefined4 *)((ulong)uVar4 * 0x10 + param_1 + 8) = 0;
  if (*(int *)((ulong)uVar4 * 0x10 + param_1) == 0) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  else {
    *(undefined2 *)(param_1 + 0xa0) = 0;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_001051c4 at 001051c4
//==================================================

void FUN_001051c4(long param_1)

{
  byte bVar1;
  undefined1 uVar2;
  undefined1 uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar4 = (uint)bVar1;
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar2 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar3 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if ((*(int *)((ulong)uVar4 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar4 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar4 * 0x10 + param_1));
  }
  iVar5 = FUN_00103e48(param_1,uVar2);
  iVar6 = FUN_00103e48(param_1,uVar3);
  *(int *)((ulong)uVar4 * 0x10 + param_1) = iVar5 * iVar6;
  *(undefined4 *)((ulong)uVar4 * 0x10 + param_1 + 8) = 0;
  if (*(int *)((ulong)uVar4 * 0x10 + param_1) == 0) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  else {
    *(undefined2 *)(param_1 + 0xa0) = 0;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00105348 at 00105348
//==================================================

void FUN_00105348(long param_1)

{
  byte bVar1;
  undefined1 uVar2;
  undefined1 uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar4 = (uint)bVar1;
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar2 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar3 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if ((*(int *)((ulong)uVar4 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar4 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar4 * 0x10 + param_1));
  }
  uVar5 = FUN_00103e48(param_1,uVar2);
  uVar6 = FUN_00103e48(param_1,uVar3);
  *(uint *)((ulong)uVar4 * 0x10 + param_1) = uVar5 ^ uVar6;
  *(undefined4 *)((ulong)uVar4 * 0x10 + param_1 + 8) = 0;
  if (*(int *)((ulong)uVar4 * 0x10 + param_1) == 0) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  else {
    *(undefined2 *)(param_1 + 0xa0) = 0;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_001054cb at 001054cb
//==================================================

void FUN_001054cb(long param_1)

{
  byte bVar1;
  undefined1 uVar2;
  undefined1 uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar4 = (uint)bVar1;
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar2 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar3 = FUN_00103fe0(param_1);
  if (9 < uVar4) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if ((*(int *)((ulong)uVar4 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar4 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar4 * 0x10 + param_1));
  }
  uVar5 = FUN_00103e48(param_1,uVar2);
  uVar6 = FUN_00103e48(param_1,uVar3);
  *(uint *)((ulong)uVar4 * 0x10 + param_1) = uVar5 | uVar6;
  *(undefined4 *)((ulong)uVar4 * 0x10 + param_1 + 8) = 0;
  if (*(int *)((ulong)uVar4 * 0x10 + param_1) == 0) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  else {
    *(undefined2 *)(param_1 + 0xa0) = 0;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_0010564e at 0010564e
//==================================================

void FUN_0010564e(long param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar2 = (uint)bVar1;
  if (9 < uVar2) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  iVar3 = FUN_00103e48(param_1,uVar2);
  *(int *)((ulong)uVar2 * 0x10 + param_1) = iVar3 + 1;
  if (*(int *)((ulong)uVar2 * 0x10 + param_1) == 0) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  else {
    *(undefined2 *)(param_1 + 0xa0) = 0;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00105701 at 00105701
//==================================================

void FUN_00105701(long param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar2 = (uint)bVar1;
  if (9 < uVar2) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  iVar3 = FUN_00103e48(param_1,uVar2);
  *(int *)((ulong)uVar2 * 0x10 + param_1) = iVar3 + -1;
  if (*(int *)((ulong)uVar2 * 0x10 + param_1) == 0) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  else {
    *(undefined2 *)(param_1 + 0xa0) = 0;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_001057b4 at 001057b4
//==================================================

void FUN_001057b4(long param_1)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar2 = (uint)bVar1;
  if (9 < uVar2) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  bVar1 = FUN_00103fe0(param_1);
  uVar3 = (uint)bVar1;
  if (9 < uVar3) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  *(undefined2 *)(param_1 + 0xa0) = 0;
  if (*(int *)((ulong)uVar2 * 0x10 + param_1 + 8) == *(int *)((ulong)uVar3 * 0x10 + param_1 + 8)) {
    if (*(int *)((ulong)uVar2 * 0x10 + param_1 + 8) == 1) {
      iVar4 = strcmp(*(char **)((ulong)uVar2 * 0x10 + param_1),
                     *(char **)((ulong)uVar3 * 0x10 + param_1));
      if (iVar4 == 0) {
        *(undefined2 *)(param_1 + 0xa0) = 1;
      }
    }
    else if (*(int *)((ulong)uVar2 * 0x10 + param_1) == *(int *)((ulong)uVar3 * 0x10 + param_1)) {
      *(undefined2 *)(param_1 + 0xa0) = 1;
    }
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00105901 at 00105901
//==================================================

void FUN_00105901(long param_1)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  int iVar4;
  
  bVar1 = FUN_00103fe0(param_1);
  if (9 < bVar1) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  bVar2 = FUN_00103fe0(param_1);
  bVar3 = FUN_00103fe0(param_1);
  *(undefined2 *)(param_1 + 0xa0) = 0;
  iVar4 = FUN_00103e48(param_1,bVar1);
  if (iVar4 == (uint)bVar2 + (uint)bVar3 * 0x100) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_001059c3 at 001059c3
//==================================================

void FUN_001059c3(long param_1)

{
  byte bVar1;
  int iVar2;
  char *__s2;
  char *__s1;
  
  bVar1 = FUN_00103fe0(param_1);
  if (9 < bVar1) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  __s2 = (char *)FUN_00103ea6(param_1);
  __s1 = (char *)FUN_00103de8(param_1,bVar1);
  iVar2 = strcmp(__s1,__s2);
  if (iVar2 == 0) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  else {
    *(undefined2 *)(param_1 + 0xa0) = 0;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00105a73 at 00105a73
//==================================================

void FUN_00105a73(long param_1)

{
  byte bVar1;
  
  bVar1 = FUN_00103fe0(param_1);
  if (9 < bVar1) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if (*(int *)((ulong)(uint)bVar1 * 0x10 + param_1 + 8) == 1) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  else {
    *(undefined2 *)(param_1 + 0xa0) = 0;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00105b00 at 00105b00
//==================================================

void FUN_00105b00(long param_1)

{
  byte bVar1;
  
  bVar1 = FUN_00103fe0(param_1);
  if (9 < bVar1) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if (*(int *)((ulong)(uint)bVar1 * 0x10 + param_1 + 8) == 0) {
    *(undefined2 *)(param_1 + 0xa0) = 1;
  }
  else {
    *(undefined2 *)(param_1 + 0xa0) = 0;
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00105b8c at 00105b8c
//==================================================

void FUN_00105b8c(long param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  
  bVar1 = FUN_00103fe0(param_1);
  uVar2 = (uint)bVar1;
  if (9 < uVar2) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  bVar1 = FUN_00103fe0(param_1);
  if (9 < bVar1) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  iVar3 = FUN_00103e48(param_1,bVar1);
  if ((iVar3 < 0) || (0xffff < iVar3)) {
    FUN_00103935(param_1,"Reading from outside RAM");
  }
  bVar1 = *(byte *)((long)iVar3 + *(long *)(param_1 + 0xa8));
  if ((*(int *)((ulong)uVar2 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar2 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar2 * 0x10 + param_1));
  }
  *(uint *)((ulong)uVar2 * 0x10 + param_1) = (uint)bVar1;
  *(undefined4 *)((ulong)uVar2 * 0x10 + param_1 + 8) = 0;
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00105cda at 00105cda
//==================================================

void FUN_00105cda(long param_1)

{
  byte bVar1;
  byte bVar2;
  undefined1 uVar3;
  int iVar4;
  
  bVar1 = FUN_00103fe0(param_1);
  if (9 < bVar1) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  bVar2 = FUN_00103fe0(param_1);
  if (9 < bVar2) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar3 = FUN_00103e48(param_1,bVar1);
  iVar4 = FUN_00103e48(param_1,bVar2);
  if ((iVar4 < 0) || (0xffff < iVar4)) {
    FUN_00103935(param_1,"Writing outside RAM");
  }
  *(undefined1 *)((long)iVar4 + *(long *)(param_1 + 0xa8)) = uVar3;
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00105dc5 at 00105dc5
//==================================================

void FUN_00105dc5(long param_1)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int local_2c;
  int local_28;
  int local_24;
  
  bVar1 = FUN_00103fe0(param_1);
  if (9 < bVar1) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  bVar2 = FUN_00103fe0(param_1);
  if (9 < bVar2) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  bVar3 = FUN_00103fe0(param_1);
  if (9 < bVar3) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  iVar4 = FUN_00103e48(param_1,bVar2);
  iVar5 = FUN_00103e48(param_1,bVar1);
  iVar6 = FUN_00103e48(param_1,bVar3);
  if ((iVar4 < 0) || (iVar5 < 0)) {
    FUN_00103935(param_1,"cannot copy to/from negative addresses");
  }
  else {
    for (local_2c = 0; local_2c < iVar6; local_2c = local_2c + 1) {
      local_24 = local_2c + iVar5;
      for (local_28 = local_2c + iVar4; 0xfffe < local_28; local_28 = local_28 + -0xffff) {
      }
      for (; 0xfffe < local_24; local_24 = local_24 + -0xffff) {
      }
      *(undefined1 *)(*(long *)(param_1 + 0xa8) + (long)local_24) =
           *(undefined1 *)(*(long *)(param_1 + 0xa8) + (long)local_28);
    }
    *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  }
  return;
}



//==================================================
// Function: FUN_00105f56 at 00105f56
//==================================================

void FUN_00105f56(long param_1)

{
  byte bVar1;
  undefined4 uVar2;
  
  bVar1 = FUN_00103fe0(param_1);
  if (9 < bVar1) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  uVar2 = FUN_00103e48(param_1,bVar1);
  *(int *)(param_1 + 0x18c0) = *(int *)(param_1 + 0x18c0) + 1;
  *(undefined4 *)(param_1 + ((long)*(int *)(param_1 + 0x18c0) + 0x230) * 4) = uVar2;
  if (0x3ff < *(int *)(param_1 + 0x18c0)) {
    FUN_00103935(param_1,"stack overflow - stack is full");
  }
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00106023 at 00106023
//==================================================

void FUN_00106023(long param_1)

{
  undefined4 uVar1;
  byte bVar2;
  uint uVar3;
  
  bVar2 = FUN_00103fe0(param_1);
  uVar3 = (uint)bVar2;
  if (9 < uVar3) {
    FUN_00103935(param_1,"Register out of bounds");
  }
  if (*(int *)(param_1 + 0x18c0) < 1) {
    FUN_00103935(param_1,"stack overflow - stack is empty");
  }
  uVar1 = *(undefined4 *)(param_1 + ((long)*(int *)(param_1 + 0x18c0) + 0x230) * 4);
  *(int *)(param_1 + 0x18c0) = *(int *)(param_1 + 0x18c0) + -1;
  if ((*(int *)((ulong)uVar3 * 0x10 + param_1 + 8) == 1) &&
     (*(long *)((ulong)uVar3 * 0x10 + param_1) != 0)) {
    free(*(void **)((ulong)uVar3 * 0x10 + param_1));
  }
  *(undefined4 *)((ulong)uVar3 * 0x10 + param_1) = uVar1;
  *(undefined4 *)((ulong)uVar3 * 0x10 + param_1 + 8) = 0;
  *(int *)(param_1 + 0xa4) = *(int *)(param_1 + 0xa4) + 1;
  return;
}



//==================================================
// Function: FUN_00106147 at 00106147
//==================================================

void FUN_00106147(long param_1)

{
  undefined4 uVar1;
  
  if (*(int *)(param_1 + 0x18c0) < 1) {
    FUN_00103935(param_1,"stack overflow - stack is empty");
  }
  uVar1 = *(undefined4 *)(param_1 + ((long)*(int *)(param_1 + 0x18c0) + 0x230) * 4);
  *(int *)(param_1 + 0x18c0) = *(int *)(param_1 + 0x18c0) + -1;
  *(undefined4 *)(param_1 + 0xa4) = uVar1;
  return;
}



//==================================================
// Function: FUN_001061c0 at 001061c0
//==================================================

void FUN_001061c0(long param_1)

{
  byte bVar1;
  byte bVar2;
  
  bVar1 = FUN_00103fe0(param_1);
  bVar2 = FUN_00103fe0(param_1);
  *(int *)(param_1 + 0x18c0) = *(int *)(param_1 + 0x18c0) + 1;
  if (0x3ff < *(int *)(param_1 + 0x18c0)) {
    FUN_00103935(param_1,"stack overflow - stack is full!");
  }
  *(int *)(param_1 + ((long)*(int *)(param_1 + 0x18c0) + 0x230) * 4) = *(int *)(param_1 + 0xa4) + 1;
  *(uint *)(param_1 + 0xa4) = (uint)bVar1 + (uint)bVar2 * 0x100;
  return;
}



//==================================================
// Function: FUN_0010627f at 0010627f
//==================================================

void FUN_0010627f(long param_1)

{
  time_t tVar1;
  int local_c;
  
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  for (local_c = 0; local_c < 0x100; local_c = local_c + 1) {
    *(code **)(param_1 + ((long)local_c + 0x18) * 8) = FUN_00104041;
  }
  *(code **)(param_1 + 0xc0) = FUN_001040b1;
  *(code **)(param_1 + 200) = FUN_00104422;
  *(code **)(param_1 + 0xd0) = FUN_00104521;
  *(code **)(param_1 + 0xd8) = FUN_001045a6;
  *(code **)(param_1 + 0xe0) = FUN_00104696;
  *(code **)(param_1 + 0x140) = FUN_00104beb;
  *(code **)(param_1 + 0x150) = FUN_00104cbc;
  *(code **)(param_1 + 0x148) = FUN_00104c3f;
  *(code **)(param_1 + 0x1c8) = FUN_00104d39;
  *(code **)(param_1 + 0x1f8) = FUN_00104ebe;
  *(code **)(param_1 + 0x1d0) = FUN_00105041;
  *(code **)(param_1 + 0x1d8) = FUN_001051c4;
  *(code **)(param_1 + 0x1e0) = FUN_0010410a;
  *(code **)(param_1 + 0x1c0) = FUN_00105348;
  *(code **)(param_1 + 0x200) = FUN_001054cb;
  *(code **)(param_1 + 0x1e8) = FUN_0010564e;
  *(code **)(param_1 + 0x1f0) = FUN_00105701;
  *(code **)(param_1 + 0x240) = FUN_00104788;
  *(code **)(param_1 + 0x248) = FUN_00104865;
  *(code **)(param_1 + 0x250) = FUN_001048ed;
  *(code **)(param_1 + 600) = FUN_00104aaf;
  *(code **)(param_1 + 0x260) = FUN_00104b2b;
  *(code **)(param_1 + 0x2c0) = FUN_001057b4;
  *(code **)(param_1 + 0x2c8) = FUN_00105901;
  *(code **)(param_1 + 0x2d0) = FUN_001059c3;
  *(code **)(param_1 + 0x2d8) = FUN_00105a73;
  *(code **)(param_1 + 0x2e0) = FUN_00105b00;
  *(code **)(param_1 + 0x340) = FUN_001040e4;
  *(code **)(param_1 + 0x348) = FUN_001042ac;
  *(code **)(param_1 + 0x3c0) = FUN_00105b8c;
  *(code **)(param_1 + 0x3c8) = FUN_00105cda;
  *(code **)(param_1 + 0x3d0) = FUN_00105dc5;
  *(code **)(param_1 + 0x440) = FUN_00105f56;
  *(code **)(param_1 + 0x448) = FUN_00106023;
  *(code **)(param_1 + 0x450) = FUN_00106147;
  *(code **)(param_1 + 0x458) = FUN_001061c0;
  return;
}



//==================================================
// Function: FUN_0010655a at 0010655a
//==================================================

void FUN_0010655a(long param_1,long param_2)

{
  long lVar1;
  uint uVar2;
  uint uVar3;
  long in_FS_OFFSET;
  uint local_20;
  byte local_14;
  byte local_13;
  byte local_12;
  byte local_11;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  for (local_20 = 0; local_20 < 4; local_20 = local_20 + 1) {
    *(undefined1 *)(param_1 + (ulong)(local_20 << 2)) =
         *(undefined1 *)(param_2 + (ulong)(local_20 << 2));
    *(undefined1 *)(param_1 + (ulong)(local_20 * 4 + 1)) =
         *(undefined1 *)(param_2 + (ulong)(local_20 * 4 + 1));
    *(undefined1 *)(param_1 + (ulong)(local_20 * 4 + 2)) =
         *(undefined1 *)(param_2 + (ulong)(local_20 * 4 + 2));
    *(undefined1 *)(param_1 + (ulong)(local_20 * 4 + 3)) =
         *(undefined1 *)(param_2 + (ulong)(local_20 * 4 + 3));
  }
  for (local_20 = 4; local_20 < 0x2c; local_20 = local_20 + 1) {
    uVar2 = (local_20 - 1) * 4;
    local_14 = *(byte *)(param_1 + (ulong)uVar2);
    local_13 = *(byte *)(param_1 + (ulong)(uVar2 + 1));
    local_12 = *(byte *)(param_1 + (ulong)(uVar2 + 2));
    local_11 = *(byte *)(param_1 + (ulong)(uVar2 + 3));
    if ((local_20 & 3) == 0) {
      uVar2 = (uint)local_13;
      local_13 = (&DAT_001085a0)[(int)(uint)local_12];
      local_12 = (&DAT_001085a0)[(int)(uint)local_11];
      local_11 = (&DAT_001085a0)[(int)(uint)local_14];
      local_14 = (&DAT_001087a0)[local_20 >> 2] ^ (&DAT_001085a0)[(int)uVar2];
    }
    uVar2 = local_20 * 4;
    uVar3 = (local_20 - 4) * 4;
    *(byte *)(param_1 + (ulong)uVar2) = local_14 ^ *(byte *)(param_1 + (ulong)uVar3);
    *(byte *)(param_1 + (ulong)(uVar2 + 1)) = local_13 ^ *(byte *)(param_1 + (ulong)(uVar3 + 1));
    *(byte *)(param_1 + (ulong)(uVar2 + 2)) = local_12 ^ *(byte *)(param_1 + (ulong)(uVar3 + 2));
    *(byte *)(param_1 + (ulong)(uVar2 + 3)) = local_11 ^ *(byte *)(param_1 + (ulong)(uVar3 + 3));
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: FUN_00106819 at 00106819
//==================================================

void FUN_00106819(undefined8 param_1,undefined8 param_2)

{
  FUN_0010655a(param_1,param_2);
  return;
}



//==================================================
// Function: FUN_00106843 at 00106843
//==================================================

void FUN_00106843(long param_1,undefined8 param_2,undefined8 *param_3)

{
  undefined8 uVar1;
  
  FUN_0010655a(param_1,param_2);
  uVar1 = param_3[1];
  *(undefined8 *)(param_1 + 0xb0) = *param_3;
  *(undefined8 *)(param_1 + 0xb8) = uVar1;
  return;
}



//==================================================
// Function: FUN_0010688e at 0010688e
//==================================================

void FUN_0010688e(long param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  
  uVar1 = param_2[1];
  *(undefined8 *)(param_1 + 0xb0) = *param_2;
  *(undefined8 *)(param_1 + 0xb8) = uVar1;
  return;
}



//==================================================
// Function: FUN_001068be at 001068be
//==================================================

void FUN_001068be(byte param_1,long param_2,long param_3)

{
  undefined1 local_a;
  undefined1 local_9;
  
  for (local_a = 0; local_a < 4; local_a = local_a + 1) {
    for (local_9 = 0; local_9 < 4; local_9 = local_9 + 1) {
      *(byte *)((long)(int)(uint)local_a * 4 + param_2 + (long)(int)(uint)local_9) =
           *(byte *)(param_3 + (int)((uint)local_9 + ((uint)local_a + (uint)param_1 * 4) * 4)) ^
           *(byte *)((long)(int)(uint)local_a * 4 + param_2 + (long)(int)(uint)local_9);
    }
  }
  return;
}



//==================================================
// Function: FUN_00106963 at 00106963
//==================================================

void FUN_00106963(long param_1)

{
  byte local_a;
  byte local_9;
  
  for (local_a = 0; local_a < 4; local_a = local_a + 1) {
    for (local_9 = 0; local_9 < 4; local_9 = local_9 + 1) {
      *(undefined *)((long)(int)(uint)local_9 * 4 + param_1 + (long)(int)(uint)local_a) =
           (&DAT_001085a0)
           [(int)(uint)*(byte *)((long)(int)(uint)local_9 * 4 + param_1 + (long)(int)(uint)local_a)]
      ;
    }
  }
  return;
}



//==================================================
// Function: FUN_001069df at 001069df
//==================================================

void FUN_001069df(long param_1)

{
  undefined1 uVar1;
  
  uVar1 = *(undefined1 *)(param_1 + 1);
  *(undefined1 *)(param_1 + 1) = *(undefined1 *)(param_1 + 5);
  *(undefined1 *)(param_1 + 5) = *(undefined1 *)(param_1 + 9);
  *(undefined1 *)(param_1 + 9) = *(undefined1 *)(param_1 + 0xd);
  *(undefined1 *)(param_1 + 0xd) = uVar1;
  uVar1 = *(undefined1 *)(param_1 + 2);
  *(undefined1 *)(param_1 + 2) = *(undefined1 *)(param_1 + 10);
  *(undefined1 *)(param_1 + 10) = uVar1;
  uVar1 = *(undefined1 *)(param_1 + 6);
  *(undefined1 *)(param_1 + 6) = *(undefined1 *)(param_1 + 0xe);
  *(undefined1 *)(param_1 + 0xe) = uVar1;
  uVar1 = *(undefined1 *)(param_1 + 3);
  *(undefined1 *)(param_1 + 3) = *(undefined1 *)(param_1 + 0xf);
  *(undefined1 *)(param_1 + 0xf) = *(undefined1 *)(param_1 + 0xb);
  *(undefined1 *)(param_1 + 0xb) = *(undefined1 *)(param_1 + 7);
  *(undefined1 *)(param_1 + 7) = uVar1;
  return;
}



//==================================================
// Function: FUN_00106abe at 00106abe
//==================================================

uint FUN_00106abe(byte param_1)

{
  return (uint)(param_1 >> 7) * 0x1b ^ (uint)param_1 * 2;
}



//==================================================
// Function: FUN_00106aef at 00106aef
//==================================================

void FUN_00106aef(long param_1)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  undefined1 local_c;
  
  for (local_c = 0; local_c < 4; local_c = local_c + 1) {
    bVar3 = *(byte *)(param_1 + (long)(int)(uint)local_c * 4);
    bVar1 = *(byte *)(param_1 + 3 + (long)(int)(uint)local_c * 4) ^
            *(byte *)(param_1 + (long)(int)(uint)local_c * 4) ^
            *(byte *)(param_1 + 1 + (long)(int)(uint)local_c * 4) ^
            *(byte *)(param_1 + 2 + (long)(int)(uint)local_c * 4);
    bVar2 = FUN_00106abe(*(byte *)(param_1 + 1 + (long)(int)(uint)local_c * 4) ^
                         *(byte *)(param_1 + (long)(int)(uint)local_c * 4));
    *(byte *)(param_1 + (long)(int)(uint)local_c * 4) =
         *(byte *)(param_1 + (long)(int)(uint)local_c * 4) ^ bVar2 ^ bVar1;
    bVar2 = FUN_00106abe(*(byte *)(param_1 + 2 + (long)(int)(uint)local_c * 4) ^
                         *(byte *)(param_1 + 1 + (long)(int)(uint)local_c * 4));
    *(byte *)(param_1 + 1 + (long)(int)(uint)local_c * 4) =
         *(byte *)(param_1 + 1 + (long)(int)(uint)local_c * 4) ^ bVar2 ^ bVar1;
    bVar2 = FUN_00106abe(*(byte *)(param_1 + 3 + (long)(int)(uint)local_c * 4) ^
                         *(byte *)(param_1 + 2 + (long)(int)(uint)local_c * 4));
    *(byte *)(param_1 + 2 + (long)(int)(uint)local_c * 4) =
         *(byte *)(param_1 + 2 + (long)(int)(uint)local_c * 4) ^ bVar2 ^ bVar1;
    bVar3 = FUN_00106abe(*(byte *)(param_1 + 3 + (long)(int)(uint)local_c * 4) ^ bVar3);
    *(byte *)(param_1 + 3 + (long)(int)(uint)local_c * 4) =
         *(byte *)(param_1 + 3 + (long)(int)(uint)local_c * 4) ^ bVar3 ^ bVar1;
  }
  return;
}



//==================================================
// Function: FUN_00106cce at 00106cce
//==================================================

void FUN_00106cce(long param_1)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  undefined1 uVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  byte bVar10;
  byte bVar11;
  byte bVar12;
  byte bVar13;
  undefined4 local_1c;
  
  for (local_1c = 0; local_1c < 4; local_1c = local_1c + 1) {
    bVar1 = *(byte *)(param_1 + (long)local_1c * 4);
    bVar2 = *(byte *)(param_1 + 1 + (long)local_1c * 4);
    bVar3 = *(byte *)(param_1 + 2 + (long)local_1c * 4);
    bVar13 = *(byte *)(param_1 + 3 + (long)local_1c * 4);
    uVar4 = FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar2);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(bVar13);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    bVar5 = FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(bVar1);
    bVar6 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(uVar4);
    bVar7 = FUN_00106abe(uVar4);
    bVar8 = FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(uVar4);
    bVar9 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar3);
    bVar10 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(uVar4);
    bVar11 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(uVar4);
    bVar12 = FUN_00106abe(uVar4);
    *(byte *)(param_1 + (long)local_1c * 4) =
         bVar5 ^ bVar6 ^ bVar7 ^ bVar9 ^ bVar8 ^ bVar2 ^ bVar11 ^ bVar10 ^ bVar3 ^ bVar12 ^ bVar13;
    FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(bVar1);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar3);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(uVar4);
    bVar5 = FUN_00106abe(uVar4);
    bVar6 = FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(bVar2);
    bVar7 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(uVar4);
    bVar8 = FUN_00106abe(uVar4);
    bVar9 = FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(uVar4);
    bVar10 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar13);
    bVar11 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(uVar4);
    bVar12 = FUN_00106abe(uVar4);
    *(byte *)(param_1 + 1 + (long)local_1c * 4) =
         bVar5 ^ bVar1 ^ bVar8 ^ bVar6 ^ bVar7 ^ bVar10 ^ bVar9 ^ bVar3 ^ bVar12 ^ bVar11 ^ bVar13;
    FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(bVar2);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar13);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar1);
    bVar5 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(uVar4);
    bVar6 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(uVar4);
    bVar7 = FUN_00106abe(uVar4);
    bVar8 = FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(bVar3);
    bVar9 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(uVar4);
    bVar10 = FUN_00106abe(uVar4);
    bVar11 = FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(uVar4);
    bVar12 = FUN_00106abe(uVar4);
    *(byte *)(param_1 + 2 + (long)local_1c * 4) =
         bVar5 ^ bVar1 ^ bVar6 ^ bVar7 ^ bVar2 ^ bVar10 ^ bVar8 ^ bVar9 ^ bVar12 ^ bVar11 ^ bVar13;
    uVar4 = FUN_00106abe(bVar1);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(bVar3);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(uVar4);
    FUN_00106abe(uVar4);
    bVar5 = FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(bVar1);
    uVar4 = FUN_00106abe(uVar4);
    bVar6 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar2);
    bVar7 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar2);
    uVar4 = FUN_00106abe(uVar4);
    bVar8 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar3);
    uVar4 = FUN_00106abe(uVar4);
    bVar9 = FUN_00106abe(uVar4);
    bVar10 = FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(bVar13);
    bVar11 = FUN_00106abe(uVar4);
    uVar4 = FUN_00106abe(bVar13);
    uVar4 = FUN_00106abe(uVar4);
    bVar13 = FUN_00106abe(uVar4);
    *(byte *)(param_1 + 3 + (long)local_1c * 4) =
         bVar5 ^ bVar1 ^ bVar6 ^ bVar8 ^ bVar7 ^ bVar2 ^ bVar9 ^ bVar3 ^ bVar13 ^ bVar10 ^ bVar11;
  }
  return;
}



//==================================================
// Function: FUN_0010749c at 0010749c
//==================================================

void FUN_0010749c(long param_1)

{
  byte local_a;
  byte local_9;
  
  for (local_a = 0; local_a < 4; local_a = local_a + 1) {
    for (local_9 = 0; local_9 < 4; local_9 = local_9 + 1) {
      *(undefined *)((long)(int)(uint)local_9 * 4 + param_1 + (long)(int)(uint)local_a) =
           (&DAT_001086a0)
           [(int)(uint)*(byte *)((long)(int)(uint)local_9 * 4 + param_1 + (long)(int)(uint)local_a)]
      ;
    }
  }
  return;
}



//==================================================
// Function: FUN_00107518 at 00107518
//==================================================

void FUN_00107518(long param_1)

{
  undefined1 uVar1;
  
  uVar1 = *(undefined1 *)(param_1 + 0xd);
  *(undefined1 *)(param_1 + 0xd) = *(undefined1 *)(param_1 + 9);
  *(undefined1 *)(param_1 + 9) = *(undefined1 *)(param_1 + 5);
  *(undefined1 *)(param_1 + 5) = *(undefined1 *)(param_1 + 1);
  *(undefined1 *)(param_1 + 1) = uVar1;
  uVar1 = *(undefined1 *)(param_1 + 2);
  *(undefined1 *)(param_1 + 2) = *(undefined1 *)(param_1 + 10);
  *(undefined1 *)(param_1 + 10) = uVar1;
  uVar1 = *(undefined1 *)(param_1 + 6);
  *(undefined1 *)(param_1 + 6) = *(undefined1 *)(param_1 + 0xe);
  *(undefined1 *)(param_1 + 0xe) = uVar1;
  uVar1 = *(undefined1 *)(param_1 + 3);
  *(undefined1 *)(param_1 + 3) = *(undefined1 *)(param_1 + 7);
  *(undefined1 *)(param_1 + 7) = *(undefined1 *)(param_1 + 0xb);
  *(undefined1 *)(param_1 + 0xb) = *(undefined1 *)(param_1 + 0xf);
  *(undefined1 *)(param_1 + 0xf) = uVar1;
  return;
}



//==================================================
// Function: FUN_001075f7 at 001075f7
//==================================================

void FUN_001075f7(undefined8 param_1,undefined8 param_2)

{
  undefined1 local_9;
  
  FUN_001068be(0,param_1,param_2);
  local_9 = '\x01';
  while( true ) {
    FUN_00106963(param_1);
    FUN_001069df(param_1);
    if (local_9 == '\n') break;
    FUN_00106aef(param_1);
    FUN_001068be(local_9,param_1,param_2);
    local_9 = local_9 + '\x01';
  }
  FUN_001068be(10,param_1,param_2);
  return;
}



//==================================================
// Function: FUN_00107687 at 00107687
//==================================================

void FUN_00107687(undefined8 param_1,undefined8 param_2)

{
  undefined1 local_9;
  
  FUN_001068be(10,param_1,param_2);
  local_9 = '\t';
  while( true ) {
    FUN_00107518(param_1);
    FUN_0010749c(param_1);
    FUN_001068be(local_9,param_1,param_2);
    if (local_9 == '\0') break;
    FUN_00106cce(param_1);
    local_9 = local_9 + -1;
  }
  return;
}



//==================================================
// Function: FUN_00107702 at 00107702
//==================================================

void FUN_00107702(undefined8 param_1,undefined8 param_2)

{
  FUN_001075f7(param_2,param_1);
  return;
}



//==================================================
// Function: FUN_0010772c at 0010772c
//==================================================

void FUN_0010772c(undefined8 param_1,undefined8 param_2)

{
  FUN_00107687(param_2,param_1);
  return;
}



//==================================================
// Function: FUN_00107756 at 00107756
//==================================================

void FUN_00107756(long param_1,long param_2)

{
  undefined1 local_9;
  
  for (local_9 = 0; local_9 < 0x10; local_9 = local_9 + 1) {
    *(byte *)(param_1 + (ulong)local_9) =
         *(byte *)(param_2 + (ulong)local_9) ^ *(byte *)(param_1 + (ulong)local_9);
  }
  return;
}



//==================================================
// Function: FUN_001077a5 at 001077a5
//==================================================

void FUN_001077a5(long param_1,undefined8 *param_2,ulong param_3)

{
  undefined8 uVar1;
  undefined8 *local_28;
  ulong local_18;
  undefined8 *local_10;
  
  local_10 = (undefined8 *)(param_1 + 0xb0);
  local_28 = param_2;
  for (local_18 = 0; local_18 < param_3; local_18 = local_18 + 0x10) {
    FUN_00107756(local_28,local_10);
    FUN_001075f7(local_28,param_1);
    local_10 = local_28;
    local_28 = local_28 + 2;
  }
  uVar1 = local_10[1];
  *(undefined8 *)(param_1 + 0xb0) = *local_10;
  *(undefined8 *)(param_1 + 0xb8) = uVar1;
  return;
}



//==================================================
// Function: FUN_00107837 at 00107837
//==================================================

void FUN_00107837(long param_1,undefined8 *param_2,ulong param_3)

{
  long lVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  long in_FS_OFFSET;
  undefined8 *local_48;
  ulong local_30;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  local_48 = param_2;
  for (local_30 = 0; local_30 < param_3; local_30 = local_30 + 0x10) {
    uVar2 = local_48[1];
    uVar3 = *local_48;
    FUN_00107687(local_48,param_1);
    FUN_00107756(local_48,param_1 + 0xb0);
    *(undefined8 *)(param_1 + 0xb0) = uVar3;
    *(undefined8 *)(param_1 + 0xb8) = uVar2;
    local_48 = local_48 + 2;
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: FUN_001078ed at 001078ed
//==================================================

void FUN_001078ed(long param_1,long param_2,ulong param_3)

{
  long in_FS_OFFSET;
  int local_34;
  ulong local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_30 = 0;
  local_34 = 0x10;
  do {
    if (param_3 <= local_30) {
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    if (local_34 == 0x10) {
      local_20 = *(undefined8 *)(param_1 + 0xb8);
      local_28 = *(undefined8 *)(param_1 + 0xb0);
      FUN_001075f7(&local_28,param_1);
      for (local_34 = 0xf; -1 < local_34; local_34 = local_34 + -1) {
        if (*(char *)(param_1 + 0xb0 + (long)local_34) != -1) {
          *(char *)(param_1 + 0xb0 + (long)local_34) =
               *(char *)(param_1 + 0xb0 + (long)local_34) + '\x01';
          break;
        }
        *(undefined1 *)(param_1 + 0xb0 + (long)local_34) = 0;
      }
      local_34 = 0;
    }
    *(byte *)(local_30 + param_2) =
         *(byte *)((long)&local_28 + (long)local_34) ^ *(byte *)(local_30 + param_2);
    local_30 = local_30 + 1;
    local_34 = local_34 + 1;
  } while( true );
}



//==================================================
// Function: _DT_FINI at 00107a1c
//==================================================

void _DT_FINI(void)

{
  return;
}


