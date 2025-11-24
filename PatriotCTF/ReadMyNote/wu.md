## Pseudo-code phân tích đoạn code C
ReadMyNote
A fun little walk in the woods! Everything you need is located within the binary! The binary was poorly obfuscated with Qengine 2.0! It can be solved either dynamically or statically. The binary has a static base! Flag format is pctf{...}

```

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_14000f2e8(void)

{
  DWORD DVar1;
  _FILETIME local_res8;
  LARGE_INTEGER local_res10;
  _FILETIME local_18 [2];
  
  if (DAT_140013040 == 0x2b992ddfa232) {
    local_res8.dwLowDateTime = 0;
    local_res8.dwHighDateTime = 0;
    GetSystemTimeAsFileTime(&local_res8);
    local_18[0] = local_res8;
    DVar1 = GetCurrentThreadId();
    local_18[0] = (_FILETIME)((ulonglong)local_18[0] ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_18[0] = (_FILETIME)((ulonglong)local_18[0] ^ (ulonglong)DVar1);
    QueryPerformanceCounter(&local_res10);
    DAT_140013040 =
         ((ulonglong)local_res10.s.LowPart << 0x20 ^
          CONCAT44(local_res10.s.HighPart,local_res10.s.LowPart) ^ (ulonglong)local_18[0] ^
         (ulonglong)local_18) & 0xffffffffffff;
    if (DAT_140013040 == 0x2b992ddfa232) {
      DAT_140013040 = 0x2b992ddfa233;
    }
  }
  _DAT_140013080 = ~DAT_140013040;
  return;
}


/* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */

int FUN_14000ed84(void)

{
  bool bVar1;
  bool bVar2;
  int iVar3;
  undefined8 uVar4;
  longlong *plVar5;
  ulonglong uVar6;
  uint *puVar7;
  undefined8 unaff_RBX;
  undefined8 in_R9;
  undefined1 uVar8;
  
  iVar3 = (int)unaff_RBX;
  uVar4 = FUN_14000ea60(1);
  if ((char)uVar4 == '\0') {
    FUN_14000f210(7);
  }
  else {
    bVar1 = false;
    uVar8 = 0;
    uVar4 = __scrt_acquire_startup_lock();
    iVar3 = (int)CONCAT71((int7)((ulonglong)unaff_RBX >> 8),(char)uVar4);
    if (DAT_140013180 != 1) {
      if (DAT_140013180 == 0) {
        DAT_140013180 = 1;
        iVar3 = _initterm_e(&DAT_140010330,&DAT_140010348);
        if (iVar3 != 0) {
          return 0xff;
        }
        _initterm(&DAT_1400102d8,&DAT_140010328);
        DAT_140013180 = 2;
      }
      else {
        bVar1 = true;
        uVar8 = 1;
      }
      __scrt_release_startup_lock((char)uVar4);
      plVar5 = (longlong *)FUN_14000f3ec();
      if ((*plVar5 != 0) && (uVar6 = FUN_14000eb28((longlong)plVar5), (char)uVar6 != '\0')) {
        (*(code *)*plVar5)(0,2,0,in_R9,uVar8);
      }
      plVar5 = (longlong *)FUN_14000f3f4();
      if ((*plVar5 != 0) && (uVar6 = FUN_14000eb28((longlong)plVar5), (char)uVar6 != '\0')) {
        _register_thread_local_exe_atexit_callback(*plVar5);
      }
      _get_initial_narrow_environment();
      __p___argv();
      puVar7 = (uint *)__p___argc();
      uVar6 = (ulonglong)*puVar7;
      iVar3 = FUN_140003890();
      bVar2 = FUN_14000f224();
      if (bVar2) {
        if (!bVar1) {
          _cexit();
        }
        __scrt_uninitialize_crt(CONCAT71((int7)(uVar6 >> 8),1),'\0');
        return iVar3;
      }
      goto LAB_14000eef0;
    }
  }
  FUN_14000f210(7);
LAB_14000eef0:
                    /* WARNING: Subroutine does not return */
  exit(iVar3);
}


longlong FUN_14000ea60(int param_1)

{
  char cVar1;
  uint7 extraout_var;
  uint7 uVar2;
  undefined7 extraout_var_00;
  uint7 extraout_var_01;
  
  if (param_1 == 0) {
    DAT_140013190 = 1;
  }
  FUN_14000ef60();
  cVar1 = FUN_14000f3b0();
  uVar2 = extraout_var;
  if (cVar1 != '\0') {
    cVar1 = FUN_14000f3b0();
    if (cVar1 != '\0') {
      return CONCAT71(extraout_var_00,1);
    }
    FUN_14000f3b0();
    uVar2 = extraout_var_01;
  }
  return (ulonglong)uVar2 << 8;
}


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_140001200(void)

{
  undefined8 *puVar1;
  byte *pbVar2;
  undefined8 local_78 [2];
  byte local_68 [8];
  undefined4 local_60;
  undefined2 local_5c;
  undefined4 local_58;
  undefined2 local_54;
  undefined4 local_50;
  undefined2 local_4c;
  undefined4 local_48;
  undefined2 local_44;
  undefined4 local_40;
  undefined2 local_3c;
  undefined4 local_38;
  undefined2 local_34;
  undefined4 local_30;
  undefined2 local_2c;
  undefined4 local_28;
  undefined2 local_24;
  undefined4 local_20;
  undefined2 local_1c;
  undefined4 local_18;
  undefined2 local_14;
  byte local_10 [8];
  
  local_68[0] = 0;
  local_68[1] = 0;
  local_68[2] = 0;
  local_68[3] = 0;
  local_68[4] = 7;
  local_68[5] = 3;
  local_60 = 1;
  local_5c = 0x105;
  local_58 = 2;
  local_54 = 0x101;
  local_50 = 3;
  local_4c = 0x206;
  local_48 = 4;
  local_44 = 0x300;
  local_40 = 5;
  local_3c = 0x300;
  local_38 = 6;
  local_34 = 0x300;
  local_30 = 7;
  local_2c = 0x300;
  local_28 = 8;
  local_24 = 0x300;
  local_20 = 9;
  local_1c = 0x300;
  local_18 = 10;
  local_14 = 0x200;
  DAT_140013bf8 = operator_new(0x18);
  *(void **)DAT_140013bf8 = DAT_140013bf8;
  *(void **)((longlong)DAT_140013bf8 + 8) = DAT_140013bf8;
  DAT_140013c08 = 0;
  _DAT_140013c10 = 0;
  uRam0000000140013c18 = 0;
  DAT_140013c20 = 7;
  DAT_140013c28 = 8;
  DAT_140013bf0 = 0x3f800000;
  puVar1 = &DAT_140013c08;
  FUN_14000e290(&DAT_140013c08,0x10,DAT_140013bf8);
  pbVar2 = local_68;
  do {
    FUN_14000e400(puVar1,local_78,pbVar2);
    pbVar2 = pbVar2 + 8;
  } while (pbVar2 != local_10);
  atexit((_func_5014 *)&LAB_14000f850);
  return;
}


undefined8 * FUN_140001340(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  return param_1;
}


char * FUN_140001380(longlong param_1)

{
  char *pcVar1;
  
  pcVar1 = "Unknown exception";
  if (*(char **)(param_1 + 8) != (char *)0x0) {
    pcVar1 = *(char **)(param_1 + 8);
  }
  return pcVar1;
}


undefined8 * FUN_1400013a0(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}


undefined8 * FUN_140001410(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad array new length";
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}


void FUN_140001440(void)

{
  undefined8 local_28 [5];
  
  FUN_140001410(local_28);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_140011710);
}


undefined8 * FUN_140001460(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}


undefined8 * FUN_1400014a0(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = 0;
  param_1[2] = 0;
  __std_exception_copy(param_2 + 8);
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}


void FUN_1400014e0(void)

{
  code *pcVar1;
  
  std::_Xlength_error("string too long");
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


undefined8 FUN_140001500(longlong param_1,ulonglong param_2,char param_3)

{
  byte bVar1;
  char cVar2;
  undefined8 in_RAX;
  byte bVar3;
  ulonglong uVar4;
  
  bVar1 = DAT_1400130c0;
  if (param_3 == '\0') {
    uVar4 = 0;
    if (param_2 != 0) {
      do {
        *(byte *)(param_1 + uVar4) = *(char *)(param_1 + uVar4) - bVar1;
        uVar4 = uVar4 + 1;
      } while (uVar4 < param_2);
    }
  }
  else {
    uVar4 = 0;
    if (param_2 != 0) {
      do {
        bVar3 = ~*(byte *)(param_1 + uVar4);
        if (bVar3 < bVar1) {
          cVar2 = (bVar1 - bVar3) + -1;
        }
        else {
          cVar2 = *(byte *)(param_1 + uVar4) + bVar1;
        }
        *(char *)(param_1 + uVar4) = cVar2;
        uVar4 = uVar4 + 1;
      } while (uVar4 < param_2);
      return 1;
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),1);
}


undefined8 FUN_140001580(longlong param_1,ulonglong param_2,char param_3)

{
  byte bVar1;
  ulonglong uVar2;
  char cVar3;
  byte bVar4;
  
  FUN_140001500(param_1,param_2,param_3);
  bVar1 = DAT_1400130c4;
  uVar2 = 0;
  if (param_3 == '\0') {
    if (param_2 != 0) {
      do {
        bVar4 = ~*(byte *)(param_1 + uVar2);
        if (bVar4 < bVar1) {
          cVar3 = (bVar1 - bVar4) + -1;
        }
        else {
          cVar3 = *(byte *)(param_1 + uVar2) + bVar1;
        }
        *(char *)(param_1 + uVar2) = cVar3;
        uVar2 = uVar2 + 1;
      } while (uVar2 < param_2);
    }
  }
  else if (param_2 != 0) {
    do {
      *(byte *)(param_1 + uVar2) = *(char *)(param_1 + uVar2) - bVar1;
      uVar2 = uVar2 + 1;
    } while (uVar2 < param_2);
    return CONCAT71((int7)(uVar2 >> 8),1);
  }
  return CONCAT71((int7)(uVar2 >> 8),1);
}


undefined8 FUN_140001630(longlong param_1,ulonglong param_2,char param_3)

{
  byte bVar1;
  char cVar2;
  undefined8 uVar3;
  byte bVar4;
  ulonglong uVar5;
  
  FUN_140001500(param_1,param_2,param_3);
  uVar3 = FUN_140001580(param_1,param_2,param_3);
  bVar1 = DAT_1400130c2;
  uVar5 = 0;
  if (param_3 == '\0') {
    if (param_2 != 0) {
      do {
        *(byte *)(param_1 + uVar5) = *(char *)(param_1 + uVar5) - bVar1;
        uVar5 = uVar5 + 1;
      } while (uVar5 < param_2);
    }
  }
  else if (param_2 != 0) {
    do {
      bVar4 = ~*(byte *)(param_1 + uVar5);
      if (bVar4 < bVar1) {
        cVar2 = (bVar1 - bVar4) + -1;
      }
      else {
        cVar2 = *(byte *)(param_1 + uVar5) + bVar1;
      }
      *(char *)(param_1 + uVar5) = cVar2;
      uVar5 = uVar5 + 1;
    } while (uVar5 < param_2);
    return 1;
  }
  return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
}


undefined8 FUN_1400016f0(longlong param_1,ulonglong param_2,char param_3)

{
  byte bVar1;
  char cVar2;
  undefined8 uVar3;
  ulonglong uVar4;
  byte bVar5;
  
  FUN_140001500(param_1,param_2,param_3);
  FUN_140001580(param_1,param_2,param_3);
  uVar3 = FUN_140001630(param_1,param_2,param_3);
  bVar1 = DAT_1400130c8;
  uVar4 = 0;
  if (param_3 == '\0') {
    if (param_2 != 0) {
      do {
        bVar5 = ~*(byte *)(param_1 + uVar4);
        if (bVar5 < bVar1) {
          cVar2 = (bVar1 - bVar5) + -1;
        }
        else {
          cVar2 = *(byte *)(param_1 + uVar4) + bVar1;
        }
        uVar3 = 0;
        *(char *)(param_1 + uVar4) = cVar2;
        uVar4 = uVar4 + 1;
      } while (uVar4 < param_2);
    }
  }
  else if (param_2 != 0) {
    do {
      *(byte *)(param_1 + uVar4) = *(char *)(param_1 + uVar4) - bVar1;
      uVar4 = uVar4 + 1;
    } while (uVar4 < param_2);
    return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
  }
  return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
}


undefined8 FUN_1400017b0(longlong param_1,ulonglong param_2,char param_3)

{
  byte bVar1;
  char cVar2;
  undefined8 uVar3;
  ulonglong uVar4;
  byte bVar5;
  
  FUN_140001500(param_1,param_2,param_3);
  FUN_140001580(param_1,param_2,param_3);
  FUN_140001630(param_1,param_2,param_3);
  uVar3 = FUN_1400016f0(param_1,param_2,param_3);
  bVar1 = DAT_1400130c6;
  uVar4 = 0;
  if (param_3 == '\0') {
    if (param_2 != 0) {
      do {
        *(byte *)(param_1 + uVar4) = *(char *)(param_1 + uVar4) - bVar1;
        uVar4 = uVar4 + 1;
      } while (uVar4 < param_2);
    }
  }
  else if (param_2 != 0) {
    do {
      bVar5 = ~*(byte *)(param_1 + uVar4);
      if (bVar5 < bVar1) {
        cVar2 = (bVar1 - bVar5) + -1;
      }
      else {
        cVar2 = *(byte *)(param_1 + uVar4) + bVar1;
      }
      *(char *)(param_1 + uVar4) = cVar2;
      uVar4 = uVar4 + 1;
    } while (uVar4 < param_2);
    return 1;
  }
  return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
}


undefined8 FUN_140001890(longlong param_1,ulonglong param_2,char param_3)

{
  byte bVar1;
  char cVar2;
  undefined8 uVar3;
  ulonglong uVar4;
  byte bVar5;
  
  FUN_140001500(param_1,param_2,param_3);
  FUN_140001580(param_1,param_2,param_3);
  FUN_140001630(param_1,param_2,param_3);
  FUN_1400016f0(param_1,param_2,param_3);
  uVar3 = FUN_1400017b0(param_1,param_2,param_3);
  bVar1 = DAT_1400130c1;
  uVar4 = 0;
  if (param_3 == '\0') {
    if (param_2 != 0) {
      do {
        bVar5 = ~*(byte *)(param_1 + uVar4);
        if (bVar5 < bVar1) {
          cVar2 = (bVar1 - bVar5) + -1;
        }
        else {
          cVar2 = *(byte *)(param_1 + uVar4) + bVar1;
        }
        uVar3 = 0;
        *(char *)(param_1 + uVar4) = cVar2;
        uVar4 = uVar4 + 1;
      } while (uVar4 < param_2);
    }
  }
  else if (param_2 != 0) {
    do {
      *(byte *)(param_1 + uVar4) = *(char *)(param_1 + uVar4) - bVar1;
      uVar4 = uVar4 + 1;
    } while (uVar4 < param_2);
    return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
  }
  return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
}


undefined8 FUN_140001970(longlong param_1,ulonglong param_2,char param_3)

{
  byte bVar1;
  char cVar2;
  undefined8 uVar3;
  byte bVar4;
  ulonglong uVar5;
  
  FUN_140001500(param_1,param_2,param_3);
  FUN_140001580(param_1,param_2,param_3);
  FUN_140001630(param_1,param_2,param_3);
  FUN_1400016f0(param_1,param_2,param_3);
  FUN_1400017b0(param_1,param_2,param_3);
  uVar3 = FUN_140001890(param_1,param_2,param_3);
  bVar1 = DAT_1400130c3;
  uVar5 = 0;
  if (param_3 == '\0') {
    if (param_2 != 0) {
      do {
        *(byte *)(param_1 + uVar5) = *(char *)(param_1 + uVar5) - bVar1;
        uVar5 = uVar5 + 1;
      } while (uVar5 < param_2);
    }
  }
  else if (param_2 != 0) {
    do {
      bVar4 = ~*(byte *)(param_1 + uVar5);
      if (bVar4 < bVar1) {
        cVar2 = (bVar1 - bVar4) + -1;
      }
      else {
        cVar2 = *(byte *)(param_1 + uVar5) + bVar1;
      }
      *(char *)(param_1 + uVar5) = cVar2;
      uVar5 = uVar5 + 1;
    } while (uVar5 < param_2);
    return 1;
  }
  return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
}


undefined8 FUN_140001a70(longlong param_1,ulonglong param_2,char param_3)

{
  byte bVar1;
  char cVar2;
  undefined8 uVar3;
  byte bVar4;
  ulonglong uVar5;
  
  FUN_140001500(param_1,param_2,param_3);
  FUN_140001580(param_1,param_2,param_3);
  FUN_140001630(param_1,param_2,param_3);
  FUN_1400016f0(param_1,param_2,param_3);
  FUN_1400017b0(param_1,param_2,param_3);
  FUN_140001890(param_1,param_2,param_3);
  uVar3 = FUN_140001970(param_1,param_2,param_3);
  bVar1 = DAT_1400130c9;
  uVar5 = 0;
  if (param_3 == '\0') {
    if (param_2 != 0) {
      do {
        bVar4 = ~*(byte *)(param_1 + uVar5);
        if (bVar4 < bVar1) {
          cVar2 = (bVar1 - bVar4) + -1;
        }
        else {
          cVar2 = *(byte *)(param_1 + uVar5) + bVar1;
        }
        uVar3 = 0;
        *(char *)(param_1 + uVar5) = cVar2;
        uVar5 = uVar5 + 1;
      } while (uVar5 < param_2);
    }
  }
  else if (param_2 != 0) {
    do {
      *(byte *)(param_1 + uVar5) = *(char *)(param_1 + uVar5) - bVar1;
      uVar5 = uVar5 + 1;
    } while (uVar5 < param_2);
    return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
  }
  return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
}


undefined8 FUN_140001b70(longlong param_1,ulonglong param_2,char param_3)

{
  byte bVar1;
  char cVar2;
  undefined8 uVar3;
  byte bVar4;
  ulonglong uVar5;
  
  FUN_140001500(param_1,param_2,param_3);
  FUN_140001580(param_1,param_2,param_3);
  FUN_140001630(param_1,param_2,param_3);
  FUN_1400016f0(param_1,param_2,param_3);
  FUN_1400017b0(param_1,param_2,param_3);
  FUN_140001890(param_1,param_2,param_3);
  FUN_140001970(param_1,param_2,param_3);
  uVar3 = FUN_140001a70(param_1,param_2,param_3);
  bVar1 = DAT_1400130c5;
  uVar5 = 0;
  if (param_3 == '\0') {
    if (param_2 != 0) {
      do {
        *(byte *)(param_1 + uVar5) = *(char *)(param_1 + uVar5) - bVar1;
        uVar5 = uVar5 + 1;
      } while (uVar5 < param_2);
    }
  }
  else if (param_2 != 0) {
    do {
      bVar4 = ~*(byte *)(param_1 + uVar5);
      if (bVar4 < bVar1) {
        cVar2 = (bVar1 - bVar4) + -1;
      }
      else {
        cVar2 = *(byte *)(param_1 + uVar5) + bVar1;
      }
      *(char *)(param_1 + uVar5) = cVar2;
      uVar5 = uVar5 + 1;
    } while (uVar5 < param_2);
    return 1;
  }
  return CONCAT71((int7)((ulonglong)uVar3 >> 8),1);
}


ulonglong FUN_140001c90(void)

{
  longlong *plVar1;
  ulonglong *puVar2;
  byte bVar3;
  uint uVar4;
  int iVar5;
  longlong *in_RAX;
  longlong lVar6;
  longlong lVar7;
  undefined8 *puVar8;
  longlong *plVar9;
  ushort uVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  longlong lVar13;
  ulonglong local_res8;
  ulonglong local_res10;
  ulonglong local_res18;
  ulonglong local_res20;
  ulonglong local_78;
  ulonglong local_70;
  ulonglong local_68;
  ulonglong local_60;
  ulonglong local_58 [3];
  
  if (DAT_140013219 == '\0') {
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      uVar4 = (int)lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        iVar5 = (int)((ulonglong)lVar6 >> 0x18) - (int)(lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        iVar5 = (int)(((lVar7 % lVar6) * 1000000000) / lVar6);
      }
      uVar4 = iVar5 + (int)lVar13 * 1000000000;
    }
    srand(uVar4 ^ 0xca);
    uVar12 = 0;
    uVar11 = uVar12;
    do {
      lVar6 = _Query_perf_frequency();
      lVar7 = _Query_perf_counter();
      if (lVar6 == 10000000) {
        lVar7 = lVar7 * 100;
      }
      else {
        if (lVar6 == 24000000) {
          lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
          lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
          lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
          lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
          lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        }
        else {
          lVar13 = lVar7 / lVar6;
          lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
        }
        lVar7 = lVar7 + lVar13 * 1000000000;
      }
      iVar5 = rand();
      uVar10 = (ushort)(lVar7 % (longlong)iVar5 >> 0x3f);
      (&DAT_1400132c0)[uVar11] =
           (((ulonglong)(ushort)((short)(lVar7 % (longlong)iVar5) + uVar10) - (ulonglong)uVar10) + 1
           ^ 0x10) << 10 | 0x101010101010101;
      lVar6 = _Query_perf_frequency();
      lVar7 = _Query_perf_counter();
      if (lVar6 == 10000000) {
        lVar7 = lVar7 * 100;
      }
      else {
        if (lVar6 == 24000000) {
          lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
          lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
          lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
          lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
          lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        }
        else {
          lVar13 = lVar7 / lVar6;
          lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
        }
        lVar7 = lVar7 + lVar13 * 1000000000;
      }
      iVar5 = rand();
      uVar4 = (uint)(lVar7 % (longlong)iVar5 >> 0x3f) & 0x1ffff;
      (&DAT_140013340)[uVar11] =
           (((ulonglong)((int)(lVar7 % (longlong)iVar5) + uVar4 & 0x1ffff) - (ulonglong)uVar4) + 1 ^
           0x20) << 0xb | 0x101010101010101;
      lVar6 = _Query_perf_frequency();
      lVar7 = _Query_perf_counter();
      if (lVar6 == 10000000) {
        lVar7 = lVar7 * 100;
      }
      else {
        if (lVar6 == 24000000) {
          lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
          lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
          lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
          lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
          lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        }
        else {
          lVar13 = lVar7 / lVar6;
          lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
        }
        lVar7 = lVar7 + lVar13 * 1000000000;
      }
      iVar5 = rand();
      (&DAT_140013230)[uVar11] =
           ((lVar7 % (longlong)iVar5) % 0x30000 + 1U ^ 0x40) << 0xc | 0x101010101010101;
      uVar11 = uVar11 + 1;
    } while (uVar11 < 0x10);
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_14001321c = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_14001321d = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_14001321e = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_14001321f = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_1400133c0 = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_1400133c1 = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_1400133c2 = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_1400133c3 = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_1400133c4 = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_1400133c5 = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_1400133c6 = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    lVar6 = _Query_perf_frequency();
    lVar7 = _Query_perf_counter();
    if (lVar6 == 10000000) {
      lVar7 = lVar7 * 100;
    }
    else {
      if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
      }
      else {
        lVar13 = lVar7 / lVar6;
        lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
      }
      lVar7 = lVar7 + lVar13 * 1000000000;
    }
    uVar4 = rand();
    uVar4 = uVar4 & 0x8000000f;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
    }
    DAT_1400133c7 = (undefined1)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
    do {
      lVar6 = _Query_perf_frequency();
      lVar7 = _Query_perf_counter();
      if (lVar6 == 10000000) {
        lVar7 = lVar7 * 100;
      }
      else {
        if (lVar6 == 24000000) {
          lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
          lVar13 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
          lVar6 = (lVar7 + lVar13 * -24000000) * 1000000000;
          lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
          lVar7 = (lVar6 >> 0x18) - (lVar6 >> 0x3f);
        }
        else {
          lVar13 = lVar7 / lVar6;
          lVar7 = ((lVar7 % lVar6) * 1000000000) / lVar6;
        }
        lVar7 = lVar7 + lVar13 * 1000000000;
      }
      uVar4 = rand();
      uVar4 = uVar4 & 0x8000000f;
      if ((int)uVar4 < 0) {
        uVar4 = (uVar4 - 1 | 0xfffffff0) + 1;
      }
      (&DAT_140013220)[(int)uVar12] = (char)(lVar7 % (longlong)(ulonglong)(byte)((char)uVar4 + 1));
      uVar4 = (int)uVar12 + 1;
      uVar12 = (ulonglong)uVar4;
    } while (uVar4 < 0xc);
    iVar5 = rand();
    DAT_1400130c0 = DAT_1400130c0 ^ (char)iVar5 + (char)(iVar5 / 0xff);
    iVar5 = rand();
    DAT_1400130c4 = DAT_1400130c4 ^ (char)iVar5 + (char)(iVar5 / 0xff);
    iVar5 = rand();
    DAT_1400130c2 = DAT_1400130c2 ^ (char)iVar5 + (char)(iVar5 / 0xff);
    iVar5 = rand();
    DAT_1400130c8 = DAT_1400130c8 ^ (char)iVar5 + (char)(iVar5 / 0xff);
    iVar5 = rand();
    DAT_1400130c6 = DAT_1400130c6 ^ (char)iVar5 + (char)(iVar5 / 0xff);
    iVar5 = rand();
    DAT_1400130c1 = DAT_1400130c1 ^ (char)iVar5 + (char)(iVar5 / 0xff);
    iVar5 = rand();
    DAT_1400130c3 = DAT_1400130c3 ^ (char)iVar5 + (char)(iVar5 / 0xff);
    iVar5 = rand();
    DAT_1400130c9 = DAT_1400130c9 ^ (char)iVar5 + (char)(iVar5 / 0xff);
    iVar5 = rand();
    DAT_1400130c5 =
         DAT_1400130c5 ^
         (char)iVar5 +
         (((char)(iVar5 / 0xff) + (char)(iVar5 >> 0x1f)) -
         (char)((longlong)iVar5 * 0x80808081 >> 0x3f));
    DAT_1400132b0 = (undefined8 *)operator_new(0x18);
    *DAT_1400132b0 = 0;
    DAT_1400132b0[1] = 0;
    DAT_1400132b0[2] = 0;
    in_RAX = (longlong *)operator_new(0x18);
    *in_RAX = 0;
    in_RAX[1] = 0;
    in_RAX[2] = 0;
    DAT_1400132b8 = in_RAX;
    if (DAT_1400132b0 != (undefined8 *)0x0) {
      lVar6 = _Query_perf_frequency();
      lVar7 = _Query_perf_counter();
      plVar9 = DAT_1400132b8;
      if (lVar6 == 10000000) {
        bVar3 = (char)lVar7 * 'd';
      }
      else if (lVar6 == 24000000) {
        lVar6 = lVar7 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar7),8);
        lVar6 = (lVar7 + ((lVar6 >> 0x18) - (lVar6 >> 0x3f)) * -24000000) * 1000000000;
        lVar6 = lVar6 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar6),8);
        bVar3 = (char)((ulonglong)lVar6 >> 0x18) - (char)(lVar6 >> 0x3f);
      }
      else {
        bVar3 = (byte)(((lVar7 % lVar6) * 1000000000) / lVar6);
      }
      DAT_1400130c7 = DAT_1400130c7 ^ bVar3;
      local_res8 = CONCAT17(DAT_1400130c7,
                            CONCAT16(DAT_1400130c7,
                                     CONCAT15(DAT_1400130c7,
                                              CONCAT14(DAT_1400130c7,
                                                       CONCAT13(DAT_1400130c7,
                                                                CONCAT12(DAT_1400130c7,
                                                                         CONCAT11(DAT_1400130c7,
                                                                                  DAT_1400130c7)))))
                                    )) ^ 0x140001500;
      local_res10 = CONCAT17(DAT_1400130c7,
                             CONCAT16(DAT_1400130c7,
                                      CONCAT15(DAT_1400130c7,
                                               CONCAT14(DAT_1400130c7,
                                                        CONCAT13(DAT_1400130c7,
                                                                 CONCAT12(DAT_1400130c7,
                                                                          CONCAT11(DAT_1400130c7,
                                                                                   DAT_1400130c7))))
                                              ))) ^ 0x140001580;
      local_res18 = CONCAT17(DAT_1400130c7,
                             CONCAT16(DAT_1400130c7,
                                      CONCAT15(DAT_1400130c7,
                                               CONCAT14(DAT_1400130c7,
                                                        CONCAT13(DAT_1400130c7,
                                                                 CONCAT12(DAT_1400130c7,
                                                                          CONCAT11(DAT_1400130c7,
                                                                                   DAT_1400130c7))))
                                              ))) ^ 0x140001630;
      local_res20 = CONCAT17(DAT_1400130c7,
                             CONCAT16(DAT_1400130c7,
                                      CONCAT15(DAT_1400130c7,
                                               CONCAT14(DAT_1400130c7,
                                                        CONCAT13(DAT_1400130c7,
                                                                 CONCAT12(DAT_1400130c7,
                                                                          CONCAT11(DAT_1400130c7,
                                                                                   DAT_1400130c7))))
                                              ))) ^ 0x1400016f0;
      local_78 = CONCAT17(DAT_1400130c7,
                          CONCAT16(DAT_1400130c7,
                                   CONCAT15(DAT_1400130c7,
                                            CONCAT14(DAT_1400130c7,
                                                     CONCAT13(DAT_1400130c7,
                                                              CONCAT12(DAT_1400130c7,
                                                                       CONCAT11(DAT_1400130c7,
                                                                                DAT_1400130c7)))))))
                 ^ 0x1400017b0;
      local_70 = CONCAT17(DAT_1400130c7,
                          CONCAT16(DAT_1400130c7,
                                   CONCAT15(DAT_1400130c7,
                                            CONCAT14(DAT_1400130c7,
                                                     CONCAT13(DAT_1400130c7,
                                                              CONCAT12(DAT_1400130c7,
                                                                       CONCAT11(DAT_1400130c7,
                                                                                DAT_1400130c7)))))))
                 ^ 0x140001890;
      local_68 = CONCAT17(DAT_1400130c7,
                          CONCAT16(DAT_1400130c7,
                                   CONCAT15(DAT_1400130c7,
                                            CONCAT14(DAT_1400130c7,
                                                     CONCAT13(DAT_1400130c7,
                                                              CONCAT12(DAT_1400130c7,
                                                                       CONCAT11(DAT_1400130c7,
                                                                                DAT_1400130c7)))))))
                 ^ 0x140001970;
      local_60 = CONCAT17(DAT_1400130c7,
                          CONCAT16(DAT_1400130c7,
                                   CONCAT15(DAT_1400130c7,
                                            CONCAT14(DAT_1400130c7,
                                                     CONCAT13(DAT_1400130c7,
                                                              CONCAT12(DAT_1400130c7,
                                                                       CONCAT11(DAT_1400130c7,
                                                                                DAT_1400130c7)))))))
                 ^ 0x140001a70;
      local_58[0] = CONCAT17(DAT_1400130c7,
                             CONCAT16(DAT_1400130c7,
                                      CONCAT15(DAT_1400130c7,
                                               CONCAT14(DAT_1400130c7,
                                                        CONCAT13(DAT_1400130c7,
                                                                 CONCAT12(DAT_1400130c7,
                                                                          CONCAT11(DAT_1400130c7,
                                                                                   DAT_1400130c7))))
                                              ))) ^ 0x140001b70;
      puVar2 = (ulonglong *)DAT_1400132b8[1];
      if (puVar2 == (ulonglong *)DAT_1400132b8[2]) {
        FUN_14000dc50(DAT_1400132b8,puVar2,&local_res8);
        plVar9 = DAT_1400132b8;
      }
      else {
        *puVar2 = local_res8;
        plVar1 = plVar9 + 1;
        *plVar1 = *plVar1 + 8;
      }
      puVar2 = (ulonglong *)plVar9[1];
      if (puVar2 == (ulonglong *)plVar9[2]) {
        FUN_14000dc50(plVar9,puVar2,&local_res10);
        plVar9 = DAT_1400132b8;
      }
      else {
        *puVar2 = local_res10;
        plVar9[1] = plVar9[1] + 8;
      }
      puVar2 = (ulonglong *)plVar9[1];
      if (puVar2 == (ulonglong *)plVar9[2]) {
        FUN_14000dc50(plVar9,puVar2,&local_res18);
        plVar9 = DAT_1400132b8;
      }
      else {
        *puVar2 = local_res18;
        plVar9[1] = plVar9[1] + 8;
      }
      puVar2 = (ulonglong *)plVar9[1];
      if (puVar2 == (ulonglong *)plVar9[2]) {
        FUN_14000dc50(plVar9,puVar2,&local_res20);
        plVar9 = DAT_1400132b8;
      }
      else {
        *puVar2 = local_res20;
        plVar9[1] = plVar9[1] + 8;
      }
      puVar2 = (ulonglong *)plVar9[1];
      if (puVar2 == (ulonglong *)plVar9[2]) {
        FUN_14000dc50(plVar9,puVar2,&local_78);
        plVar9 = DAT_1400132b8;
      }
      else {
        *puVar2 = local_78;
        plVar9[1] = plVar9[1] + 8;
      }
      puVar2 = (ulonglong *)plVar9[1];
      if (puVar2 == (ulonglong *)plVar9[2]) {
        FUN_14000dc50(plVar9,puVar2,&local_70);
        plVar9 = DAT_1400132b8;
      }
      else {
        *puVar2 = local_70;
        plVar9[1] = plVar9[1] + 8;
      }
      puVar2 = (ulonglong *)plVar9[1];
      if (puVar2 == (ulonglong *)plVar9[2]) {
        FUN_14000dc50(plVar9,puVar2,&local_68);
        plVar9 = DAT_1400132b8;
      }
      else {
        *puVar2 = local_68;
        plVar9[1] = plVar9[1] + 8;
      }
      puVar2 = (ulonglong *)plVar9[1];
      if (puVar2 == (ulonglong *)plVar9[2]) {
        FUN_14000dc50(plVar9,puVar2,&local_60);
        plVar9 = DAT_1400132b8;
      }
      else {
        *puVar2 = local_60;
        plVar9[1] = plVar9[1] + 8;
      }
      puVar2 = (ulonglong *)plVar9[1];
      if (puVar2 != (ulonglong *)plVar9[2]) {
        *puVar2 = local_58[0];
        plVar9[1] = plVar9[1] + 8;
        DAT_140013219 = 1;
        return CONCAT71((int7)(local_58[0] >> 8),1);
      }
      puVar8 = FUN_14000dc50(plVar9,puVar2,local_58);
      DAT_140013219 = 1;
      return CONCAT71((int7)((ulonglong)puVar8 >> 8),1);
    }
  }
  return (ulonglong)in_RAX & 0xffffffffffffff00;
}


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_140002f60(longlong param_1)

{
  void *_Src;
  longlong *plVar1;
  byte *pbVar2;
  longlong *plVar3;
  byte *pbVar4;
  byte bVar5;
  void *_Dst;
  byte bVar6;
  ulonglong uVar7;
  longlong lVar8;
  byte bVar9;
  byte bVar10;
  byte bVar11;
  ulonglong uVar12;
  byte bVar13;
  byte bVar14;
  byte bVar15;
  undefined1 auStack_58 [32];
  ulonglong local_38;
  
  plVar3 = DAT_1400132b0;
  local_38 = DAT_140013040 ^ (ulonglong)auStack_58;
  if ((param_1 != 0) && (DAT_1400132b0 != (longlong *)0x0)) {
    pbVar4 = (byte *)*DAT_1400132b0;
    pbVar2 = (byte *)DAT_1400132b0[1];
    if (pbVar2 != pbVar4) {
      do {
        *pbVar4 = *pbVar4 ^ DAT_1400130c7;
        bVar5 = pbVar4[1] ^ DAT_1400130c7;
        pbVar4[1] = bVar5;
        bVar6 = pbVar4[2] ^ DAT_1400130c7;
        pbVar4[2] = bVar6;
        bVar11 = pbVar4[3] ^ DAT_1400130c7;
        pbVar4[3] = bVar11;
        bVar13 = pbVar4[4] ^ DAT_1400130c7;
        pbVar4[4] = bVar13;
        bVar14 = pbVar4[5] ^ DAT_1400130c7;
        pbVar4[5] = bVar14;
        bVar15 = DAT_1400130c7 ^ pbVar4[6];
        pbVar4[6] = bVar15;
        bVar10 = pbVar4[7] ^ DAT_1400130c7;
        pbVar4[7] = bVar10;
        bVar9 = (byte)*(longlong *)pbVar4;
        if (*(longlong *)pbVar4 == param_1) {
          *pbVar4 = bVar9 ^ DAT_1400130c7;
          pbVar4[1] = bVar5 ^ DAT_1400130c7;
          pbVar4[2] = bVar6 ^ DAT_1400130c7;
          pbVar4[3] = bVar11 ^ DAT_1400130c7;
          pbVar4[4] = bVar13 ^ DAT_1400130c7;
          pbVar4[5] = bVar14 ^ DAT_1400130c7;
          pbVar4[6] = bVar15 ^ DAT_1400130c7;
          pbVar4[7] = bVar10 ^ DAT_1400130c7;
          _DAT_140013208 = pbVar4;
          if (pbVar4 != (byte *)0x0) {
            uVar7 = (plVar3[1] - *plVar3 >> 1) * 0x4ec4ec4ec4ec4ec5;
            if ((*(ulonglong *)(pbVar4 + 10) < uVar7 - 1) &&
               (uVar12 = *(ulonglong *)(pbVar4 + 10) + 1, uVar12 < uVar7)) {
              do {
                lVar8 = uVar12 * 0x1a;
                uVar12 = uVar12 + 1;
                plVar1 = (longlong *)(lVar8 + 10 + *plVar3);
                *plVar1 = *plVar1 + -1;
              } while (uVar12 < (ulonglong)((plVar3[1] - *plVar3 >> 1) * 0x4ec4ec4ec4ec4ec5));
            }
            _Dst = (void *)(*(longlong *)(pbVar4 + 10) * 0x1a + *plVar3);
            _Src = (void *)((longlong)_Dst + 0x1a);
            memmove(_Dst,_Src,plVar3[1] - (longlong)_Src);
            plVar3[1] = plVar3[1] + -0x1a;
          }
          goto LAB_14000309b;
        }
        *pbVar4 = bVar9 ^ DAT_1400130c7;
        pbVar4[1] = bVar5 ^ DAT_1400130c7;
        pbVar4[2] = bVar6 ^ DAT_1400130c7;
        pbVar4[3] = bVar11 ^ DAT_1400130c7;
        pbVar4[4] = bVar13 ^ DAT_1400130c7;
        pbVar4[5] = bVar14 ^ DAT_1400130c7;
        pbVar4[6] = bVar15 ^ DAT_1400130c7;
        pbVar4[7] = bVar10 ^ DAT_1400130c7;
        pbVar4 = pbVar4 + 0x1a;
      } while (pbVar4 != pbVar2);
      _DAT_140013208 = (byte *)0x0;
    }
  }
LAB_14000309b:
  FUN_14000e8e0(local_38 ^ (ulonglong)auStack_58);
  return;
}


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

byte * FUN_140003190(longlong param_1,undefined8 param_2)

{
  longlong *plVar1;
  undefined8 *puVar2;
  longlong lVar3;
  longlong lVar4;
  ulonglong uVar5;
  byte *pbVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  byte bVar10;
  byte bVar11;
  byte bVar12;
  longlong lVar13;
  longlong *plVar14;
  byte bVar15;
  byte bVar16;
  byte bStack_47;
  byte bStack_46;
  byte bStack_45;
  byte bStack_44;
  byte bStack_43;
  byte bStack_42;
  byte bStack_41;
  byte local_40;
  byte bStack_3f;
  byte bStack_3e;
  byte bStack_3d;
  byte bStack_3c;
  byte bStack_3b;
  byte bStack_3a;
  byte bStack_39;
  byte bStack_38;
  undefined1 uStack_37;
  undefined6 uStack_36;
  undefined2 uStack_30;
  undefined8 uStack_2e;
  
  if ((param_1 == 0) || (DAT_1400132b0 == (longlong *)0x0)) {
    pbVar6 = (byte *)0x0;
  }
  else {
    pbVar6 = (byte *)DAT_1400132b0[1];
    for (_DAT_140013c30 = (byte *)*DAT_1400132b0; _DAT_140013c30 != pbVar6;
        _DAT_140013c30 = _DAT_140013c30 + 0x1a) {
      *_DAT_140013c30 = *_DAT_140013c30 ^ DAT_1400130c7;
      bVar7 = _DAT_140013c30[1] ^ DAT_1400130c7;
      _DAT_140013c30[1] = bVar7;
      bVar8 = DAT_1400130c7 ^ _DAT_140013c30[2];
      _DAT_140013c30[2] = bVar8;
      bVar11 = DAT_1400130c7 ^ _DAT_140013c30[3];
      _DAT_140013c30[3] = bVar11;
      bVar12 = DAT_1400130c7 ^ _DAT_140013c30[4];
      _DAT_140013c30[4] = bVar12;
      bVar15 = _DAT_140013c30[5] ^ DAT_1400130c7;
      _DAT_140013c30[5] = bVar15;
      bVar16 = DAT_1400130c7 ^ _DAT_140013c30[6];
      _DAT_140013c30[6] = bVar16;
      bVar9 = _DAT_140013c30[7] ^ DAT_1400130c7;
      _DAT_140013c30[7] = bVar9;
      bVar10 = (byte)*(longlong *)_DAT_140013c30;
      if (*(longlong *)_DAT_140013c30 == param_1) {
        *_DAT_140013c30 = bVar10 ^ DAT_1400130c7;
        _DAT_140013c30[1] = bVar7 ^ DAT_1400130c7;
        _DAT_140013c30[2] = bVar8 ^ DAT_1400130c7;
        _DAT_140013c30[3] = bVar11 ^ DAT_1400130c7;
        _DAT_140013c30[4] = bVar12 ^ DAT_1400130c7;
        _DAT_140013c30[5] = bVar15 ^ DAT_1400130c7;
        _DAT_140013c30[6] = bVar16 ^ DAT_1400130c7;
        _DAT_140013c30[7] = bVar9 ^ DAT_1400130c7;
        if (_DAT_140013c30 != (byte *)0x0) {
          return _DAT_140013c30;
        }
        goto LAB_1400032c5;
      }
      *_DAT_140013c30 = bVar10 ^ DAT_1400130c7;
      _DAT_140013c30[1] = bVar7 ^ DAT_1400130c7;
      _DAT_140013c30[2] = bVar8 ^ DAT_1400130c7;
      _DAT_140013c30[3] = bVar11 ^ DAT_1400130c7;
      _DAT_140013c30[4] = bVar12 ^ DAT_1400130c7;
      _DAT_140013c30[5] = bVar15 ^ DAT_1400130c7;
      _DAT_140013c30[6] = bVar16 ^ DAT_1400130c7;
      _DAT_140013c30[7] = bVar9 ^ DAT_1400130c7;
    }
    _DAT_140013c30 = (byte *)0x0;
LAB_1400032c5:
    lVar3 = _Query_perf_frequency();
    lVar4 = _Query_perf_counter();
    if (lVar3 == 10000000) {
      uVar5 = 0;
    }
    else if (lVar3 == 24000000) {
      lVar3 = lVar4 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar4),8);
      lVar3 = (lVar4 + ((lVar3 >> 0x18) - (lVar3 >> 0x3f)) * -24000000) * 1000000000;
      lVar3 = lVar3 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar3),8);
      uVar5 = (lVar3 >> 0x18) - (lVar3 >> 0x3f);
    }
    else {
      uVar5 = ((lVar4 % lVar3) * 1000000000) / lVar3;
    }
    if ((uVar5 & 1) == 0) {
      lVar3 = _Query_perf_frequency();
      lVar4 = _Query_perf_counter();
      if (lVar3 == 10000000) {
        lVar4 = lVar4 * 100;
      }
      else {
        if (lVar3 == 24000000) {
          lVar3 = lVar4 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar4),8);
          lVar13 = (lVar3 >> 0x18) - (lVar3 >> 0x3f);
          lVar3 = (lVar4 + lVar13 * -24000000) * 1000000000;
          lVar3 = lVar3 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar3),8);
          lVar4 = (lVar3 >> 0x18) - (lVar3 >> 0x3f);
        }
        else {
          lVar13 = lVar4 / lVar3;
          lVar4 = ((lVar4 % lVar3) * 1000000000) / lVar3;
        }
        lVar4 = lVar4 + lVar13 * 1000000000;
      }
      bStack_38 = (char)lVar4 + (char)(lVar4 / 9) * -9;
    }
    else {
      lVar3 = _Query_perf_frequency();
      lVar4 = _Query_perf_counter();
      if (lVar3 == 10000000) {
        lVar4 = lVar4 * 100;
      }
      else {
        if (lVar3 == 24000000) {
          lVar3 = lVar4 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar4),8);
          lVar13 = (lVar3 >> 0x18) - (lVar3 >> 0x3f);
          lVar3 = (lVar4 + lVar13 * -24000000) * 1000000000;
          lVar3 = lVar3 + SUB168(SEXT816(-0x4d0b03f86b6f730d) * SEXT816(lVar3),8);
          lVar4 = (lVar3 >> 0x18) - (lVar3 >> 0x3f);
        }
        else {
          lVar13 = lVar4 / lVar3;
          lVar4 = ((lVar4 % lVar3) * 1000000000) / lVar3;
        }
        lVar4 = lVar4 + lVar13 * 1000000000;
      }
      bStack_38 = ((char)lVar4 + (char)(lVar4 / 9) * -9) - 1;
    }
    plVar14 = DAT_1400132b0;
    uStack_37 = 0;
    puVar2 = (undefined8 *)DAT_1400132b0[1];
    lVar3 = ((longlong)puVar2 - *DAT_1400132b0 >> 1) * 0x4ec4ec4ec4ec4ec5;
    uStack_36 = (undefined6)lVar3;
    uStack_30 = (undefined2)((ulonglong)lVar3 >> 0x30);
    local_40 = DAT_1400130c7 ^ (byte)param_1;
    bStack_47 = (byte)((ulonglong)param_1 >> 8);
    bStack_3f = DAT_1400130c7 ^ bStack_47;
    bStack_46 = (byte)((ulonglong)param_1 >> 0x10);
    bStack_3e = DAT_1400130c7 ^ bStack_46;
    bStack_45 = (byte)((ulonglong)param_1 >> 0x18);
    bStack_3d = DAT_1400130c7 ^ bStack_45;
    bStack_44 = (byte)((ulonglong)param_1 >> 0x20);
    bStack_3c = DAT_1400130c7 ^ bStack_44;
    bStack_43 = (byte)((ulonglong)param_1 >> 0x28);
    bStack_3b = DAT_1400130c7 ^ bStack_43;
    bStack_42 = (byte)((ulonglong)param_1 >> 0x30);
    bStack_3a = DAT_1400130c7 ^ bStack_42;
    bStack_41 = (byte)((ulonglong)param_1 >> 0x38);
    bStack_39 = DAT_1400130c7 ^ bStack_41;
    if (puVar2 == (undefined8 *)DAT_1400132b0[2]) {
      uStack_2e = param_2;
      FUN_14000ddf0(DAT_1400132b0,puVar2,(undefined8 *)&local_40);
      plVar14 = DAT_1400132b0;
    }
    else {
      *puVar2 = CONCAT17(bStack_39,
                         CONCAT16(bStack_3a,
                                  CONCAT15(bStack_3b,
                                           CONCAT14(bStack_3c,
                                                    CONCAT13(bStack_3d,
                                                             CONCAT12(bStack_3e,
                                                                      CONCAT11(bStack_3f,local_40)))
                                                   ))));
      puVar2[1] = CONCAT62(uStack_36,(ushort)bStack_38);
      *(longlong *)((longlong)puVar2 + 10) = lVar3;
      *(undefined8 *)((longlong)puVar2 + 0x12) = param_2;
      plVar1 = plVar14 + 1;
      *plVar1 = *plVar1 + 0x1a;
    }
    pbVar6 = (byte *)(*plVar14 + -0x1a + (plVar14[1] - *plVar14 >> 1) * 2);
  }
  return pbVar6;
}


longlong * FUN_140003640(longlong *param_1,longlong param_2,longlong param_3)

{
  void *pvVar1;
  code *pcVar2;
  longlong lVar3;
  longlong *plVar4;
  ulonglong uVar5;
  void *_Memory;
  undefined1 *puVar6;
  undefined1 auStack_68 [8];
  undefined1 auStack_60 [24];
  void *local_48 [3];
  ulonglong local_30;
  
  puVar6 = auStack_68;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0xf;
  *(undefined1 *)param_1 = 0;
  plVar4 = FUN_14000d620(local_48,"MEMORY_ALTERATION");
  if (param_1 == plVar4) {
LAB_1400036f0:
    if (local_30 < 0x10) goto LAB_140003732;
    if ((0xfff < local_30 + 1) &&
       (uVar5 = (longlong)local_48[0] + (-8 - (longlong)*(void **)((longlong)local_48[0] + -8)),
       local_48[0] = *(void **)((longlong)local_48[0] + -8), puVar6 = auStack_68, 0x1f < uVar5))
    goto LAB_140003723;
  }
  else {
    if ((ulonglong)param_1[3] < 0x10) {
LAB_1400036bc:
      param_1[2] = 0;
      param_1[3] = 0xf;
      *(undefined1 *)param_1 = 0;
      lVar3 = plVar4[1];
      *param_1 = *plVar4;
      param_1[1] = lVar3;
      lVar3 = plVar4[3];
      param_1[2] = plVar4[2];
      param_1[3] = lVar3;
      plVar4[2] = 0;
      plVar4[3] = 0xf;
      *(undefined1 *)plVar4 = 0;
      goto LAB_1400036f0;
    }
    pvVar1 = (void *)*param_1;
    _Memory = pvVar1;
    if ((param_1[3] + 1U < 0x1000) ||
       (_Memory = *(void **)((longlong)pvVar1 + -8),
       (ulonglong)((longlong)pvVar1 + (-8 - (longlong)_Memory)) < 0x20)) {
      free(_Memory);
      goto LAB_1400036bc;
    }
LAB_140003723:
    pcVar2 = (code *)swi(0x29);
    local_48[0] = (void *)(*pcVar2)(5);
    puVar6 = auStack_60;
  }
  *(undefined8 *)(puVar6 + -8) = 0x140003732;
  free(local_48[0]);
LAB_140003732:
  *(undefined4 *)(param_1 + 4) = 3;
  *(undefined1 *)((longlong)param_1 + 0x24) = 0;
  param_1[5] = param_2;
  param_1[6] = param_3;
  return param_1;
}


void FUN_140003760(longlong *param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *_Memory;
  undefined1 *puVar3;
  undefined1 auStack_28 [8];
  undefined1 auStack_20 [24];
  
  if (0xf < (ulonglong)param_1[3]) {
    pvVar1 = (void *)*param_1;
    _Memory = pvVar1;
    puVar3 = auStack_28;
    if ((0xfff < param_1[3] + 1U) &&
       (_Memory = *(void **)((longlong)pvVar1 + -8), puVar3 = auStack_28,
       0x1f < (ulonglong)((longlong)pvVar1 + (-8 - (longlong)_Memory)))) {
      pcVar2 = (code *)swi(0x29);
      _Memory = (void *)(*pcVar2)(5);
      puVar3 = auStack_20;
    }
    *(undefined8 *)(puVar3 + -8) = 0x1400037a9;
    free(_Memory);
  }
  *(undefined1 *)param_1 = 0;
  param_1[3] = 0xf;
  param_1[2] = 0;
  return;
}


void FUN_1400037d0(longlong param_1)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  code *pcVar3;
  void *_Memory;
  void *pvVar4;
  undefined1 *puVar5;
  undefined1 auStack_28 [8];
  undefined1 auStack_20 [24];
  
  puVar5 = auStack_28;
  pvVar4 = *(void **)(param_1 + 0x18);
  if (pvVar4 != (void *)0x0) {
    _Memory = pvVar4;
    puVar5 = auStack_28;
    if (0xfff < (ulonglong)((*(longlong *)(param_1 + 0x28) - (longlong)pvVar4 >> 3) * 8)) {
      _Memory = *(void **)((longlong)pvVar4 + -8);
      pvVar4 = (void *)((longlong)pvVar4 + (-8 - (longlong)_Memory));
      puVar5 = auStack_28;
      if ((void *)0x1f < pvVar4) {
        pcVar3 = (code *)swi(0x29);
        _Memory = pvVar4;
        (*pcVar3)(5);
        puVar5 = auStack_20;
      }
    }
    *(undefined8 *)(puVar5 + -8) = 0x14000382c;
    free(_Memory);
    *(undefined8 *)(param_1 + 0x18) = 0;
    *(undefined8 *)(param_1 + 0x20) = 0;
    *(undefined8 *)(param_1 + 0x28) = 0;
  }
  puVar1 = *(undefined8 **)(param_1 + 8);
  *(undefined8 *)puVar1[1] = 0;
  puVar1 = (undefined8 *)*puVar1;
  while (puVar1 != (undefined8 *)0x0) {
    puVar2 = (undefined8 *)*puVar1;
    *(undefined8 *)(puVar5 + -8) = 0x14000385d;
    free(puVar1);
    puVar1 = puVar2;
  }
  free(*(void **)(param_1 + 8));
  return;
}


undefined8 FUN_140003880(void)

{
  return 0x19;
}


basic_ostream<> * FUN_14000d310(basic_ostream<> *param_1)

{
  char cVar1;
  
  cVar1 = std::basic_ios<>::widen
                    ((basic_ios<> *)(param_1 + *(int *)(*(longlong *)param_1 + 4)),'\n');
  std::basic_ostream<>::put(param_1,cVar1);
  std::basic_ostream<>::flush(param_1);
  return param_1;
}


basic_ostream<> * FUN_14000d350(basic_ostream<> *param_1)

{
  basic_ostream<> *this;
  bool bVar1;
  int iVar2;
  int iVar3;
  __int64 _Var4;
  longlong lVar5;
  longlong lVar6;
  
  iVar3 = 0;
  if (*(longlong *)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x28) < 0x11) {
    lVar6 = 0;
  }
  else {
    lVar6 = *(longlong *)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x28) + -0x10;
  }
  if (*(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) !=
      (longlong *)0x0) {
    (**(code **)(**(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) + 8)
    )();
  }
  bVar1 = std::ios_base::good((ios_base *)(param_1 + *(int *)(*(longlong *)param_1 + 4)));
  if (bVar1) {
    this = *(basic_ostream<> **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x50);
    if ((this == (basic_ostream<> *)0x0) || (this == param_1)) {
      bVar1 = true;
    }
    else {
      std::basic_ostream<>::flush(this);
      bVar1 = std::ios_base::good((ios_base *)(param_1 + *(int *)(*(longlong *)param_1 + 4)));
    }
  }
  if (bVar1 == false) {
    iVar3 = 4;
  }
  else {
    lVar5 = *(longlong *)param_1;
    if ((*(uint *)(param_1 + (longlong)*(int *)(lVar5 + 4) + 0x18) & 0x1c0) != 0x40) {
      for (; 0 < lVar6; lVar6 = lVar6 + -1) {
        iVar2 = std::basic_streambuf<>::sputc
                          (*(basic_streambuf<> **)
                            (param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48),
                           (char)param_1[(longlong)*(int *)(*(longlong *)param_1 + 4) + 0x58]);
        if (iVar2 == -1) goto LAB_14000d496;
      }
      lVar5 = *(longlong *)param_1;
    }
    _Var4 = std::basic_streambuf<>::sputn
                      (*(basic_streambuf<> **)(param_1 + (longlong)*(int *)(lVar5 + 4) + 0x48),
                       "The note reads: ",0x10);
    if (_Var4 == 0x10) {
      for (; 0 < lVar6; lVar6 = lVar6 + -1) {
        iVar2 = std::basic_streambuf<>::sputc
                          (*(basic_streambuf<> **)
                            (param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48),
                           (char)param_1[(longlong)*(int *)(*(longlong *)param_1 + 4) + 0x58]);
        if (iVar2 == -1) goto LAB_14000d496;
      }
    }
    else {
LAB_14000d496:
      iVar3 = 4;
    }
    *(undefined8 *)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x28) = 0;
  }
  std::basic_ios<>::setstate
            ((basic_ios<> *)(param_1 + *(int *)(*(longlong *)param_1 + 4)),iVar3,false);
  iVar3 = std::uncaught_exceptions();
  if (iVar3 == 0) {
    std::basic_ostream<>::_Osfx(param_1);
  }
  if (*(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) !=
      (longlong *)0x0) {
    (**(code **)(**(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) +
                0x10))();
  }
  return param_1;
}


void FUN_14000d520(longlong *param_1)

{
  code *pcVar1;
  void *_Memory;
  void *pvVar2;
  undefined1 *puVar3;
  undefined1 auStack_28 [8];
  undefined1 auStack_20 [24];
  
  pvVar2 = (void *)*param_1;
  if (pvVar2 != (void *)0x0) {
    _Memory = pvVar2;
    puVar3 = auStack_28;
    if (0xfff < (ulonglong)((param_1[2] - (longlong)pvVar2 >> 3) * 8)) {
      _Memory = *(void **)((longlong)pvVar2 + -8);
      pvVar2 = (void *)((longlong)pvVar2 + (-8 - (longlong)_Memory));
      puVar3 = auStack_28;
      if ((void *)0x1f < pvVar2) {
        pcVar1 = (code *)swi(0x29);
        _Memory = pvVar2;
        (*pcVar1)(5);
        puVar3 = auStack_20;
      }
    }
    *(undefined8 *)(puVar3 + -8) = 0x14000d575;
    free(_Memory);
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
  }
  return;
}


void FUN_14000d590(longlong *param_1)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  
  puVar1 = (undefined8 *)*param_1;
  *(undefined8 *)puVar1[1] = 0;
  puVar1 = (undefined8 *)*puVar1;
  while (puVar1 != (undefined8 *)0x0) {
    puVar2 = (undefined8 *)*puVar1;
    free(puVar1);
    puVar1 = puVar2;
  }
  free((void *)*param_1);
  return;
}


longlong * FUN_14000d5f0(longlong *param_1,longlong *param_2)

{
  size_t *psVar1;
  
  if (param_1 != param_2) {
    psVar1 = (size_t *)(param_2 + 2);
    if (0xf < (ulonglong)param_2[3]) {
      param_2 = (longlong *)*param_2;
    }
    FUN_14000e130(param_1,param_2,*psVar1);
  }
  return param_1;
}


undefined8 * FUN_14000d620(undefined8 *param_1,char *param_2)

{
  ulonglong uVar1;
  code *pcVar2;
  size_t _Size;
  ulonglong uVar3;
  ulonglong uVar4;
  void *pvVar5;
  void *_Dst;
  undefined8 *puVar6;
  undefined1 *puVar7;
  undefined8 uStack_40;
  undefined1 auStack_38 [32];
  
  puVar7 = auStack_38;
  _Dst = (void *)0x0;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  _Size = strlen(param_2);
  if (0x7fffffffffffffff < _Size) {
    FUN_1400014e0();
    pcVar2 = (code *)swi(3);
    puVar6 = (undefined8 *)(*pcVar2)();
    return puVar6;
  }
  if (_Size < 0x10) {
    param_1[2] = _Size;
    param_1[3] = 0xf;
    memcpy(param_1,param_2,_Size);
    *(undefined1 *)(_Size + (longlong)param_1) = 0;
  }
  else {
    uVar3 = _Size | 0xf;
    if (uVar3 < 0x8000000000000000) goto LAB_14000d6b6;
    uVar4 = 0x8000000000000027;
    puVar7 = auStack_38;
    uVar3 = 0x7fffffffffffffff;
    while( true ) {
      *(undefined8 *)(puVar7 + -8) = 0x14000d6aa;
      pvVar5 = operator_new(uVar4);
      if (pvVar5 != (void *)0x0) break;
      pcVar2 = (code *)swi(0x29);
      uVar3 = (*pcVar2)(5);
      puVar7 = puVar7 + 8;
LAB_14000d6b6:
      if (uVar3 < 0x16) {
        uVar3 = 0x16;
      }
      uVar1 = uVar3 + 1;
      if (uVar1 == 0) goto LAB_14000d6f8;
      if (uVar1 < 0x1000) {
        *(undefined8 *)(puVar7 + -8) = 0x14000d6f5;
        _Dst = operator_new(uVar1);
        goto LAB_14000d6f8;
      }
      uVar4 = uVar3 + 0x28;
      if (uVar4 <= uVar1) {
        *(undefined8 *)(puVar7 + -8) = 0x14000d736;
        FUN_140001440();
        pcVar2 = (code *)swi(3);
        puVar6 = (undefined8 *)(*pcVar2)();
        return puVar6;
      }
    }
    _Dst = (void *)((longlong)pvVar5 + 0x27U & 0xffffffffffffffe0);
    *(void **)((longlong)_Dst - 8) = pvVar5;
LAB_14000d6f8:
    *param_1 = _Dst;
    param_1[2] = _Size;
    param_1[3] = uVar3;
    *(undefined8 *)(puVar7 + -8) = 0x14000d711;
    memcpy(_Dst,param_2,_Size);
    *(undefined1 *)(_Size + (longlong)_Dst) = 0;
  }
  return param_1;
}


undefined8 * FUN_14000d740(undefined8 *param_1,undefined8 *param_2)

{
  ulonglong uVar1;
  ulonglong uVar2;
  code *pcVar3;
  undefined8 uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  void *pvVar7;
  void *_Dst;
  undefined8 *puVar8;
  undefined1 *puVar9;
  undefined8 uStack_40;
  undefined1 auStack_38 [32];
  
  puVar9 = auStack_38;
  *param_1 = 0;
  param_1[1] = 0;
  _Dst = (void *)0x0;
  param_1[2] = 0;
  param_1[3] = 0;
  uVar2 = param_2[2];
  if (0xf < (ulonglong)param_2[3]) {
    param_2 = (undefined8 *)*param_2;
  }
  if (0x7fffffffffffffff < uVar2) {
    FUN_1400014e0();
    pcVar3 = (code *)swi(3);
    puVar8 = (undefined8 *)(*pcVar3)();
    return puVar8;
  }
  if (uVar2 < 0x10) {
    param_1[2] = uVar2;
    param_1[3] = 0xf;
    uVar4 = param_2[1];
    *param_1 = *param_2;
    param_1[1] = uVar4;
    return param_1;
  }
  uVar5 = uVar2 | 0xf;
  if (uVar5 < 0x8000000000000000) goto LAB_14000d7db;
  uVar6 = 0x8000000000000027;
  puVar9 = auStack_38;
  uVar5 = 0x7fffffffffffffff;
  while( true ) {
    *(undefined8 *)(puVar9 + -8) = 0x14000d7cc;
    pvVar7 = operator_new(uVar6);
    if (pvVar7 != (void *)0x0) break;
    pcVar3 = (code *)swi(0x29);
    uVar5 = (*pcVar3)(5);
    puVar9 = puVar9 + 8;
LAB_14000d7db:
    if (uVar5 < 0x16) {
      uVar5 = 0x16;
    }
    uVar1 = uVar5 + 1;
    if (uVar1 == 0) goto LAB_14000d81f;
    if (uVar1 < 0x1000) {
      *(undefined8 *)(puVar9 + -8) = 0x14000d81f;
      _Dst = operator_new(uVar1);
      goto LAB_14000d81f;
    }
    uVar6 = uVar5 + 0x28;
    if (uVar6 <= uVar1) {
      *(undefined8 *)(puVar9 + -8) = 0x14000d855;
      FUN_140001440();
      pcVar3 = (code *)swi(3);
      puVar8 = (undefined8 *)(*pcVar3)();
      return puVar8;
    }
  }
  _Dst = (void *)((longlong)pvVar7 + 0x27U & 0xffffffffffffffe0);
  *(void **)((longlong)_Dst - 8) = pvVar7;
LAB_14000d81f:
  *param_1 = _Dst;
  param_1[2] = uVar2;
  param_1[3] = uVar5;
  *(undefined8 *)(puVar9 + -8) = 0x14000d839;
  memcpy(_Dst,param_2,uVar2 + 1);
  return param_1;
}


basic_ostream<> * FUN_14000d860(basic_ostream<> *param_1,char *param_2,ulonglong param_3)

{
  basic_ostream<> *this;
  bool bVar1;
  int iVar2;
  int iVar3;
  ulonglong uVar4;
  longlong lVar5;
  longlong lVar6;
  
  iVar3 = 0;
  uVar4 = *(ulonglong *)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x28);
  if (((longlong)uVar4 < 1) || (uVar4 <= param_3)) {
    lVar6 = 0;
  }
  else {
    lVar6 = uVar4 - param_3;
  }
  if (*(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) !=
      (longlong *)0x0) {
    (**(code **)(**(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) + 8)
    )();
  }
  bVar1 = std::ios_base::good((ios_base *)(param_1 + *(int *)(*(longlong *)param_1 + 4)));
  if (bVar1) {
    this = *(basic_ostream<> **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x50);
    if ((this == (basic_ostream<> *)0x0) || (this == param_1)) {
      bVar1 = true;
    }
    else {
      std::basic_ostream<>::flush(this);
      bVar1 = std::ios_base::good((ios_base *)(param_1 + *(int *)(*(longlong *)param_1 + 4)));
    }
  }
  if (bVar1 == false) {
    iVar3 = 4;
  }
  else {
    lVar5 = *(longlong *)param_1;
    if ((*(uint *)(param_1 + (longlong)*(int *)(lVar5 + 4) + 0x18) & 0x1c0) != 0x40) {
      for (; lVar6 != 0; lVar6 = lVar6 + -1) {
        iVar2 = std::basic_streambuf<>::sputc
                          (*(basic_streambuf<> **)
                            (param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48),
                           (char)param_1[(longlong)*(int *)(*(longlong *)param_1 + 4) + 0x58]);
        if (iVar2 == -1) {
          iVar3 = 4;
          goto LAB_14000d960;
        }
      }
      lVar5 = *(longlong *)param_1;
    }
    uVar4 = std::basic_streambuf<>::sputn
                      (*(basic_streambuf<> **)(param_1 + (longlong)*(int *)(lVar5 + 4) + 0x48),
                       param_2,param_3);
    if (uVar4 == param_3) {
LAB_14000d960:
      do {
        if (lVar6 == 0) goto LAB_14000d988;
        iVar2 = std::basic_streambuf<>::sputc
                          (*(basic_streambuf<> **)
                            (param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48),
                           (char)param_1[(longlong)*(int *)(*(longlong *)param_1 + 4) + 0x58]);
        if (iVar2 == -1) break;
        lVar6 = lVar6 + -1;
      } while( true );
    }
    iVar3 = 4;
LAB_14000d988:
    *(undefined8 *)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x28) = 0;
  }
  std::basic_ios<>::setstate
            ((basic_ios<> *)(param_1 + *(int *)(*(longlong *)param_1 + 4)),iVar3,false);
  iVar3 = std::uncaught_exceptions();
  if (iVar3 == 0) {
    std::basic_ostream<>::_Osfx(param_1);
  }
  if (*(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) !=
      (longlong *)0x0) {
    (**(code **)(**(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) +
                0x10))();
  }
  return param_1;
}


basic_istream<> * FUN_14000da30(basic_istream<> *param_1,longlong *param_2,undefined8 param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  longlong lVar3;
  uint uVar4;
  bool bVar5;
  bool bVar6;
  uint uVar7;
  longlong *plVar8;
  uint uVar9;
  undefined1 uVar10;
  
  uVar4 = (uint)param_3;
  uVar9 = 0;
  bVar5 = false;
  if (*(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) !=
      (longlong *)0x0) {
    (**(code **)(**(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) + 8)
    )();
  }
  bVar6 = std::basic_istream<>::_Ipfx(param_1,true);
  if (bVar6) {
    param_2[2] = 0;
    plVar8 = param_2;
    if (0xf < (ulonglong)param_2[3]) {
      plVar8 = (longlong *)*param_2;
    }
    *(undefined1 *)plVar8 = 0;
    uVar7 = std::basic_streambuf<>::sgetc
                      (*(basic_streambuf<> **)
                        (param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48));
    while (uVar7 != 0xffffffff) {
      if (uVar7 == (uVar4 & 0xff)) {
        bVar5 = true;
        std::basic_streambuf<>::sbumpc
                  (*(basic_streambuf<> **)
                    (param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48));
        goto LAB_14000db12;
      }
      uVar1 = param_2[2];
      if (0x7ffffffffffffffe < uVar1) {
        uVar9 = 2;
        goto LAB_14000db12;
      }
      uVar2 = param_2[3];
      uVar10 = (undefined1)uVar7;
      if (uVar1 < uVar2) {
        param_2[2] = uVar1 + 1;
        if (uVar2 < 0x10) {
          *(undefined1 *)(uVar1 + (longlong)param_2) = uVar10;
          *(undefined1 *)(uVar1 + 1 + (longlong)param_2) = 0;
        }
        else {
          lVar3 = *param_2;
          *(undefined1 *)(uVar1 + lVar3) = uVar10;
          *(undefined1 *)(uVar1 + 1 + lVar3) = 0;
        }
      }
      else {
        FUN_14000dfc0(param_2,uVar2,param_3,uVar10);
      }
      bVar5 = true;
      uVar7 = std::basic_streambuf<>::snextc
                        (*(basic_streambuf<> **)
                          (param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48));
    }
    uVar9 = 1;
LAB_14000db12:
    if (bVar5) goto LAB_14000db8d;
  }
  uVar9 = uVar9 | 2;
LAB_14000db8d:
  std::basic_ios<>::setstate
            ((basic_ios<> *)(param_1 + *(int *)(*(longlong *)param_1 + 4)),uVar9,false);
  if (*(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) !=
      (longlong *)0x0) {
    (**(code **)(**(longlong **)(param_1 + (longlong)*(int *)(*(longlong *)param_1 + 4) + 0x48) +
                0x10))();
  }
  return param_1;
}


void FUN_14000dbe0(longlong *param_1)

{
  longlong *plVar1;
  int iVar2;
  
  iVar2 = std::uncaught_exceptions();
  if (iVar2 == 0) {
    std::basic_ostream<>::_Osfx((basic_ostream<> *)*param_1);
  }
  plVar1 = *(longlong **)((longlong)*(int *)(*(longlong *)*param_1 + 4) + 0x48 + *param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  return;
}


undefined8 * FUN_14000dc50(longlong *param_1,void *param_2,undefined8 *param_3)

{
  ulonglong uVar1;
  code *pcVar2;
  void *pvVar3;
  undefined8 *puVar4;
  ulonglong uVar5;
  undefined8 *_Dst;
  void *_Memory;
  longlong lVar6;
  undefined8 *unaff_RBX;
  undefined1 *puVar7;
  ulonglong uVar8;
  size_t _Size;
  undefined1 auStack_48 [8];
  undefined1 auStack_40 [24];
  
  puVar4 = (undefined8 *)*param_1;
  lVar6 = param_1[1] - (longlong)puVar4 >> 3;
  if (lVar6 == 0x1fffffffffffffff) {
    FUN_14000e6b0();
    pcVar2 = (code *)swi(3);
    puVar4 = (undefined8 *)(*pcVar2)();
    return puVar4;
  }
  uVar5 = param_1[2] - (longlong)puVar4 >> 3;
  if (0x1fffffffffffffff - (uVar5 >> 1) < uVar5) {
LAB_14000dde7:
    FUN_140001440();
    pcVar2 = (code *)swi(3);
    puVar4 = (undefined8 *)(*pcVar2)();
    return puVar4;
  }
  uVar1 = lVar6 + 1;
  uVar5 = uVar5 + (uVar5 >> 1);
  uVar8 = uVar1;
  if (uVar1 <= uVar5) {
    uVar8 = uVar5;
  }
  if (0x1fffffffffffffff < uVar8) goto LAB_14000dde7;
  uVar5 = uVar8 * 8;
  if (uVar5 == 0) {
    unaff_RBX = (undefined8 *)0x0;
LAB_14000dd1d:
    puVar4 = unaff_RBX + ((longlong)param_2 - (longlong)puVar4 >> 3);
    *puVar4 = *param_3;
    pvVar3 = (void *)*param_1;
    if (param_2 == (void *)param_1[1]) {
      _Size = param_1[1] - (longlong)pvVar3;
      _Dst = unaff_RBX;
      param_2 = pvVar3;
    }
    else {
      memmove(unaff_RBX,pvVar3,(longlong)param_2 - (longlong)pvVar3);
      _Dst = puVar4 + 1;
      _Size = param_1[1] - (longlong)param_2;
    }
    memmove(_Dst,param_2,_Size);
    pvVar3 = (void *)*param_1;
    if (pvVar3 == (void *)0x0) goto LAB_14000ddb1;
    _Memory = pvVar3;
    puVar7 = auStack_48;
    if ((0xfff < (ulonglong)((param_1[2] - (longlong)pvVar3 >> 3) * 8)) &&
       (_Memory = *(void **)((longlong)pvVar3 + -8), puVar7 = auStack_48,
       0x1f < (ulonglong)((longlong)pvVar3 + (-8 - (longlong)_Memory)))) goto LAB_14000dd9f;
  }
  else {
    if (uVar5 < 0x1000) {
      unaff_RBX = (undefined8 *)operator_new(uVar5);
      goto LAB_14000dd1d;
    }
    if (uVar5 + 0x27 <= uVar5) goto LAB_14000dde7;
    pvVar3 = operator_new(uVar5 + 0x27);
    if (pvVar3 != (void *)0x0) {
      unaff_RBX = (undefined8 *)((longlong)pvVar3 + 0x27U & 0xffffffffffffffe0);
      unaff_RBX[-1] = pvVar3;
      goto LAB_14000dd1d;
    }
LAB_14000dd9f:
    _Memory = (void *)0x5;
    pcVar2 = (code *)swi(0x29);
    (*pcVar2)();
    puVar7 = auStack_40;
  }
  *(undefined8 *)(puVar7 + -8) = 0x14000ddb1;
  free(_Memory);
LAB_14000ddb1:
  *param_1 = (longlong)unaff_RBX;
  param_1[1] = (longlong)(unaff_RBX + uVar1);
  param_1[2] = (longlong)(unaff_RBX + uVar8);
  return puVar4;
}


undefined8 * FUN_14000ddf0(longlong *param_1,void *param_2,undefined8 *param_3)

{
  code *pcVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  void *pvVar4;
  ulonglong uVar5;
  void *pvVar6;
  longlong lVar7;
  void *unaff_RBX;
  undefined1 *puVar8;
  ulonglong uVar9;
  size_t _Size;
  undefined8 *puVar10;
  undefined1 auStack_58 [8];
  undefined1 auStack_50 [24];
  
  puVar10 = (undefined8 *)*param_1;
  lVar7 = (param_1[1] - (longlong)puVar10 >> 1) * 0x4ec4ec4ec4ec4ec5;
  if (lVar7 == 0x9d89d89d89d89d8) {
    FUN_14000e6b0();
    pcVar1 = (code *)swi(3);
    puVar10 = (undefined8 *)(*pcVar1)();
    return puVar10;
  }
  uVar5 = (param_1[2] - (longlong)puVar10 >> 1) * 0x4ec4ec4ec4ec4ec5;
  uVar3 = 0x9d89d89d89d89d8 - (uVar5 >> 1);
  if (uVar3 <= uVar5 && uVar5 - uVar3 != 0) {
LAB_14000dfb9:
    FUN_140001440();
    pcVar1 = (code *)swi(3);
    puVar10 = (undefined8 *)(*pcVar1)();
    return puVar10;
  }
  uVar5 = uVar5 + (uVar5 >> 1);
  uVar3 = lVar7 + 1;
  uVar9 = uVar3;
  if (uVar3 <= uVar5) {
    uVar9 = uVar5;
  }
  if (0x9d89d89d89d89d8 < uVar9) goto LAB_14000dfb9;
  uVar9 = uVar9 * 0x1a;
  if (uVar9 == 0) {
    unaff_RBX = (void *)0x0;
LAB_14000decb:
    uVar2 = param_3[1];
    puVar10 = (undefined8 *)
              ((((longlong)param_2 - (longlong)puVar10) / 0x1a) * 0x1a + (longlong)unaff_RBX);
    *puVar10 = *param_3;
    puVar10[1] = uVar2;
    uVar2 = *(undefined8 *)((longlong)param_3 + 0x12);
    *(undefined8 *)((longlong)puVar10 + 10) = *(undefined8 *)((longlong)param_3 + 10);
    *(undefined8 *)((longlong)puVar10 + 0x12) = uVar2;
    pvVar4 = (void *)*param_1;
    if (param_2 == (void *)param_1[1]) {
      _Size = param_1[1] - (longlong)pvVar4;
      pvVar6 = unaff_RBX;
      param_2 = pvVar4;
    }
    else {
      memmove(unaff_RBX,pvVar4,(longlong)param_2 - (longlong)pvVar4);
      pvVar6 = (void *)((longlong)puVar10 + 0x1a);
      _Size = param_1[1] - (longlong)param_2;
    }
    memmove(pvVar6,param_2,_Size);
    pvVar4 = (void *)*param_1;
    if (pvVar4 == (void *)0x0) goto LAB_14000df7e;
    pvVar6 = pvVar4;
    puVar8 = auStack_58;
    if ((0xfff < (ulonglong)((param_1[2] - (longlong)pvVar4 >> 1) * 2)) &&
       (pvVar6 = *(void **)((longlong)pvVar4 + -8), puVar8 = auStack_58,
       0x1f < (ulonglong)((longlong)pvVar4 + (-8 - (longlong)pvVar6)))) goto LAB_14000df6c;
  }
  else {
    if (uVar9 < 0x1000) {
      unaff_RBX = operator_new(uVar9);
      goto LAB_14000decb;
    }
    if (uVar9 + 0x27 <= uVar9) goto LAB_14000dfb9;
    pvVar4 = operator_new(uVar9 + 0x27);
    if (pvVar4 != (void *)0x0) {
      unaff_RBX = (void *)((longlong)pvVar4 + 0x27U & 0xffffffffffffffe0);
      *(void **)((longlong)unaff_RBX - 8) = pvVar4;
      goto LAB_14000decb;
    }
LAB_14000df6c:
    pvVar6 = (void *)0x5;
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)();
    puVar8 = auStack_50;
  }
  *(undefined8 *)(puVar8 + -8) = 0x14000df7e;
  free(pvVar6);
LAB_14000df7e:
  *param_1 = (longlong)unaff_RBX;
  param_1[1] = (longlong)(uVar3 * 0x1a + (longlong)unaff_RBX);
  param_1[2] = (longlong)(uVar9 + (longlong)unaff_RBX);
  return puVar10;
}


void FUN_14000dfc0(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined1 param_4)

{
  ulonglong uVar1;
  undefined8 *puVar2;
  void *pvVar3;
  size_t _Size;
  ulonglong uVar4;
  code *pcVar5;
  void *pvVar6;
  ulonglong uVar7;
  void *_Src;
  undefined1 *puVar8;
  void *unaff_RDI;
  undefined1 auStack_48 [8];
  undefined1 auStack_40 [24];
  
  puVar8 = auStack_48;
  _Size = param_1[2];
  _Src = (void *)0x7fffffffffffffff;
  if (_Size == 0x7fffffffffffffff) {
    FUN_1400014e0();
    pcVar5 = (code *)swi(3);
    (*pcVar5)();
    return;
  }
  uVar4 = param_1[3];
  pvVar6 = (void *)(_Size + 1 | 0xf);
  if ((pvVar6 < (void *)0x8000000000000000) && (uVar4 <= 0x7fffffffffffffff - (uVar4 >> 1))) {
    pvVar3 = (void *)(uVar4 + (uVar4 >> 1));
    _Src = pvVar6;
    if (pvVar6 < pvVar3) {
      _Src = pvVar3;
    }
    uVar1 = (longlong)_Src + 1;
    if (uVar1 == 0) {
      unaff_RDI = (void *)0x0;
    }
    else {
      if (0xfff < uVar1) {
        uVar7 = (longlong)_Src + 0x28;
        if (uVar7 <= uVar1) {
          FUN_140001440();
          pcVar5 = (code *)swi(3);
          (*pcVar5)();
          return;
        }
        goto LAB_14000e060;
      }
      unaff_RDI = operator_new(uVar1);
    }
LAB_14000e083:
    param_1[2] = _Size + 1;
    param_1[3] = _Src;
    if (uVar4 < 0x10) {
      memcpy(unaff_RDI,param_1,_Size);
      *(undefined1 *)(_Size + (longlong)unaff_RDI) = param_4;
      *(undefined1 *)(_Size + 1 + (longlong)unaff_RDI) = 0;
      goto LAB_14000e0f8;
    }
    _Src = (void *)*param_1;
    memcpy(unaff_RDI,_Src,_Size);
    *(undefined1 *)(_Size + (longlong)unaff_RDI) = param_4;
    *(undefined1 *)(_Size + 1 + (longlong)unaff_RDI) = 0;
    if (0xfff < uVar4 + 1) {
      puVar2 = (undefined8 *)((longlong)_Src + -8);
      _Src = (void *)((longlong)_Src + (-8 - (longlong)*puVar2));
      if (_Src < (void *)0x20) {
        free((void *)*puVar2);
        goto LAB_14000e0f8;
      }
      goto LAB_14000e0d5;
    }
  }
  else {
    uVar7 = 0x8000000000000027;
LAB_14000e060:
    pvVar6 = operator_new(uVar7);
    if (pvVar6 != (void *)0x0) {
      unaff_RDI = (void *)((longlong)pvVar6 + 0x27U & 0xffffffffffffffe0);
      *(void **)((longlong)unaff_RDI - 8) = pvVar6;
      goto LAB_14000e083;
    }
LAB_14000e0d5:
    pcVar5 = (code *)swi(0x29);
    (*pcVar5)(5);
    puVar8 = auStack_40;
  }
  *(undefined8 *)(puVar8 + -8) = 0x14000e0e4;
  free(_Src);
LAB_14000e0f8:
  *param_1 = unaff_RDI;
  return;
}


longlong * FUN_14000e130(longlong *param_1,void *param_2,size_t param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  code *pcVar3;
  void *pvVar4;
  longlong *plVar5;
  ulonglong uVar6;
  void *_Memory;
  undefined1 *puVar7;
  ulonglong uVar8;
  void *unaff_R14;
  undefined1 auStack_48 [8];
  undefined1 auStack_40 [24];
  
  uVar2 = param_1[3];
  if (param_3 <= uVar2) {
    plVar5 = param_1;
    if (0xf < uVar2) {
      plVar5 = (longlong *)*param_1;
    }
    param_1[2] = param_3;
    memmove(plVar5,param_2,param_3);
    *(undefined1 *)(param_3 + (longlong)plVar5) = 0;
    return param_1;
  }
  uVar8 = 0x7fffffffffffffff;
  if (0x7fffffffffffffff < param_3) {
    FUN_1400014e0();
    pcVar3 = (code *)swi(3);
    plVar5 = (longlong *)(*pcVar3)();
    return plVar5;
  }
  uVar6 = param_3 | 0xf;
  if ((uVar6 < 0x8000000000000000) && (uVar2 <= 0x7fffffffffffffff - (uVar2 >> 1))) {
    uVar1 = (uVar2 >> 1) + uVar2;
    uVar8 = uVar6;
    if (uVar6 < uVar1) {
      uVar8 = uVar1;
    }
    uVar1 = uVar8 + 1;
    if (uVar1 == 0) {
      unaff_R14 = (void *)0x0;
    }
    else {
      if (0xfff < uVar1) {
        uVar6 = uVar8 + 0x28;
        if (uVar6 <= uVar1) {
          FUN_140001440();
          pcVar3 = (code *)swi(3);
          plVar5 = (longlong *)(*pcVar3)();
          return plVar5;
        }
        goto LAB_14000e1eb;
      }
      unaff_R14 = operator_new(uVar1);
    }
LAB_14000e20e:
    param_1[2] = param_3;
    param_1[3] = uVar8;
    memcpy(unaff_R14,param_2,param_3);
    *(undefined1 *)((longlong)unaff_R14 + param_3) = 0;
    if (uVar2 < 0x10) goto LAB_14000e268;
    pvVar4 = (void *)*param_1;
    _Memory = pvVar4;
    puVar7 = auStack_48;
    if ((0xfff < uVar2 + 1) &&
       (_Memory = *(void **)((longlong)pvVar4 + -8), puVar7 = auStack_48,
       0x1f < (ulonglong)((longlong)pvVar4 + (-8 - (longlong)_Memory)))) goto LAB_14000e256;
  }
  else {
    uVar6 = 0x8000000000000027;
LAB_14000e1eb:
    pvVar4 = operator_new(uVar6);
    if (pvVar4 != (void *)0x0) {
      unaff_R14 = (void *)((longlong)pvVar4 + 0x27U & 0xffffffffffffffe0);
      *(void **)((longlong)unaff_R14 - 8) = pvVar4;
      goto LAB_14000e20e;
    }
LAB_14000e256:
    _Memory = (void *)0x5;
    pcVar3 = (code *)swi(0x29);
    (*pcVar3)();
    puVar7 = auStack_40;
  }
  *(undefined8 *)(puVar7 + -8) = 0x14000e268;
  free(_Memory);
LAB_14000e268:
  *param_1 = (longlong)unaff_R14;
  return param_1;
}


void FUN_14000e290(ulonglong *param_1,ulonglong param_2,undefined8 param_3)

{
  code *pcVar1;
  void *pvVar2;
  void *_Memory;
  longlong lVar3;
  ulonglong uVar4;
  undefined1 *puVar5;
  undefined8 *unaff_RDI;
  undefined8 *puVar6;
  undefined1 auStack_38 [8];
  undefined1 auStack_30 [24];
  
  puVar6 = (undefined8 *)*param_1;
  lVar3 = (longlong)param_1[1] - (longlong)puVar6;
  if (param_2 <= (ulonglong)(lVar3 >> 3)) {
    uVar4 = lVar3 + 7U >> 3;
    if ((undefined8 *)param_1[1] < puVar6) {
      uVar4 = 0;
    }
    if (uVar4 == 0) {
      return;
    }
    for (; uVar4 != 0; uVar4 = uVar4 - 1) {
      *puVar6 = param_3;
      puVar6 = puVar6 + 1;
    }
    return;
  }
  if (0x1fffffffffffffff < param_2) {
LAB_14000e3c2:
    FUN_140001440();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  uVar4 = param_2 * 8;
  if (uVar4 == 0) {
    unaff_RDI = (undefined8 *)0x0;
LAB_14000e31e:
    pvVar2 = (void *)*param_1;
    lVar3 = (longlong)(param_1[2] - (longlong)pvVar2) >> 3;
    if (lVar3 == 0) goto LAB_14000e368;
    _Memory = pvVar2;
    puVar5 = auStack_38;
    if ((0xfff < (ulonglong)(lVar3 * 8)) &&
       (_Memory = *(void **)((longlong)pvVar2 - 8), puVar5 = auStack_38,
       0x1f < (ulonglong)((longlong)pvVar2 + (-8 - (longlong)_Memory)))) goto LAB_14000e359;
  }
  else {
    if (uVar4 < 0x1000) {
      unaff_RDI = (undefined8 *)operator_new(uVar4);
      goto LAB_14000e31e;
    }
    if (uVar4 + 0x27 <= uVar4) goto LAB_14000e3c2;
    pvVar2 = operator_new(uVar4 + 0x27);
    if (pvVar2 != (void *)0x0) {
      unaff_RDI = (undefined8 *)((longlong)pvVar2 + 0x27U & 0xffffffffffffffe0);
      unaff_RDI[-1] = pvVar2;
      goto LAB_14000e31e;
    }
LAB_14000e359:
    pcVar1 = (code *)swi(0x29);
    _Memory = (void *)(*pcVar1)(5);
    puVar5 = auStack_30;
  }
  *(undefined8 *)(puVar5 + -8) = 0x14000e368;
  free(_Memory);
LAB_14000e368:
  puVar6 = unaff_RDI + param_2;
  *param_1 = (ulonglong)unaff_RDI;
  param_1[1] = (ulonglong)puVar6;
  param_1[2] = (ulonglong)puVar6;
  for (; unaff_RDI != puVar6; unaff_RDI = unaff_RDI + 1) {
    *unaff_RDI = param_3;
  }
  return;
}


void FUN_14000e3d0(longlong *param_1)

{
  longlong *plVar1;
  
  plVar1 = *(longlong **)((longlong)*(int *)(*(longlong *)*param_1 + 4) + 0x48 + *param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  return;
}


undefined8 * FUN_14000e400(undefined8 param_1,undefined8 *param_2,byte *param_3)

{
  int iVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  code *pcVar4;
  ulonglong uVar5;
  undefined8 *puVar6;
  longlong lVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  undefined8 *puVar11;
  float fVar12;
  
  uVar10 = (((((ulonglong)*param_3 ^ 0xcbf29ce484222325) * 0x100000001b3 ^ (ulonglong)param_3[1]) *
             0x100000001b3 ^ (ulonglong)param_3[2]) * 0x100000001b3 ^ (ulonglong)param_3[3]) *
           0x100000001b3;
  puVar6 = *(undefined8 **)(DAT_140013c08 + 8 + (uVar10 & DAT_140013c20) * 0x10);
  puVar11 = DAT_140013bf8;
  if (puVar6 != DAT_140013bf8) {
    iVar1 = *(int *)(puVar6 + 2);
    puVar11 = puVar6;
    while( true ) {
      if (*(int *)param_3 == iVar1) {
        *param_2 = puVar11;
        *(undefined1 *)(param_2 + 1) = 0;
        return param_2;
      }
      if (puVar11 == *(undefined8 **)(DAT_140013c08 + (uVar10 & DAT_140013c20) * 0x10)) break;
      puVar11 = (undefined8 *)puVar11[1];
      iVar1 = *(int *)(puVar11 + 2);
    }
  }
  if (DAT_140013c00 == 0xaaaaaaaaaaaaaaa) {
    std::_Xlength_error("unordered_map/set too long");
    pcVar4 = (code *)swi(3);
    puVar6 = (undefined8 *)(*pcVar4)();
    return puVar6;
  }
  puVar6 = (undefined8 *)operator_new(0x18);
  puVar6[2] = *(undefined8 *)param_3;
  uVar5 = DAT_140013c28;
  if (DAT_140013bf0 < (float)(DAT_140013c00 + 1) / (float)DAT_140013c28) {
    fVar12 = ceilf((float)(DAT_140013c00 + 1) / DAT_140013bf0);
    lVar7 = 0;
    if ((9.223372e+18 <= fVar12) && (fVar12 = fVar12 - 9.223372e+18, fVar12 < 9.223372e+18)) {
      lVar7 = -0x8000000000000000;
    }
    uVar8 = 8;
    if (8 < (ulonglong)((longlong)fVar12 + lVar7)) {
      uVar8 = (longlong)fVar12 + lVar7;
    }
    uVar9 = uVar5;
    if ((uVar5 < uVar8) && ((0x1ff < uVar5 || (uVar9 = uVar5 * 8, uVar5 * 8 < uVar8)))) {
      uVar9 = uVar8;
    }
    FUN_14000e6f0(uVar8,uVar9);
    puVar2 = *(undefined8 **)(DAT_140013c08 + 8 + (DAT_140013c20 & uVar10) * 0x10);
    puVar11 = DAT_140013bf8;
    if (puVar2 != DAT_140013bf8) {
      iVar1 = *(int *)(puVar2 + 2);
      puVar11 = puVar2;
      while (*(int *)(puVar6 + 2) != iVar1) {
        if (puVar11 == *(undefined8 **)(DAT_140013c08 + (DAT_140013c20 & uVar10) * 0x10))
        goto LAB_14000e63b;
        puVar11 = (undefined8 *)puVar11[1];
        iVar1 = *(int *)(puVar11 + 2);
      }
      puVar11 = (undefined8 *)*puVar11;
    }
  }
LAB_14000e63b:
  puVar2 = (undefined8 *)puVar11[1];
  DAT_140013c00 = DAT_140013c00 + 1;
  *puVar6 = puVar11;
  puVar6[1] = puVar2;
  *puVar2 = puVar6;
  puVar11[1] = puVar6;
  lVar7 = DAT_140013c08;
  uVar10 = DAT_140013c20 & uVar10;
  puVar3 = *(undefined8 **)(DAT_140013c08 + uVar10 * 0x10);
  if (puVar3 == DAT_140013bf8) {
    *(undefined8 **)(DAT_140013c08 + uVar10 * 0x10) = puVar6;
  }
  else {
    if (puVar3 == puVar11) {
      *(undefined8 **)(DAT_140013c08 + uVar10 * 0x10) = puVar6;
      goto LAB_14000e69a;
    }
    if (*(undefined8 **)(DAT_140013c08 + 8 + uVar10 * 0x10) != puVar2) goto LAB_14000e69a;
  }
  *(undefined8 **)(lVar7 + 8 + uVar10 * 0x10) = puVar6;
LAB_14000e69a:
  *param_2 = puVar6;
  *(undefined1 *)(param_2 + 1) = 1;
  return param_2;
}


void FUN_14000e6b0(void)

{
  code *pcVar1;
  
  std::_Xlength_error("vector too long");
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


void FUN_14000e6f0(undefined8 param_1,ulonglong param_2)

{
  undefined8 *puVar1;
  longlong *plVar2;
  longlong *plVar3;
  longlong *plVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  undefined8 *puVar7;
  code *pcVar8;
  longlong *plVar9;
  longlong *plVar10;
  ulonglong uVar11;
  longlong lVar12;
  
  plVar10 = DAT_140013bf8;
  for (lVar12 = 0x3f; 0xfffffffffffffffU >> lVar12 == 0; lVar12 = lVar12 + -1) {
  }
  if ((ulonglong)(1L << ((byte)lVar12 & 0x3f)) < param_2) {
    std::_Xlength_error("invalid hash bucket count");
    pcVar8 = (code *)swi(3);
    (*pcVar8)();
    return;
  }
  uVar11 = param_2 - 1 | 1;
  lVar12 = 0x3f;
  if (uVar11 != 0) {
    for (; uVar11 >> lVar12 == 0; lVar12 = lVar12 + -1) {
    }
  }
  lVar12 = 1L << ((char)lVar12 + 1U & 0x3f);
  FUN_14000e290((ulonglong *)&DAT_140013c08,lVar12 * 2,DAT_140013bf8);
  DAT_140013c20 = lVar12 - 1;
  DAT_140013c28 = lVar12;
  plVar9 = (longlong *)*DAT_140013bf8;
joined_r0x00014000e772:
  do {
    while( true ) {
      while( true ) {
        if (plVar9 == plVar10) {
          return;
        }
        plVar2 = (longlong *)*plVar9;
        uVar11 = (((((ulonglong)*(byte *)(plVar9 + 2) ^ 0xcbf29ce484222325) * 0x100000001b3 ^
                   (ulonglong)*(byte *)((longlong)plVar9 + 0x11)) * 0x100000001b3 ^
                  (ulonglong)*(byte *)((longlong)plVar9 + 0x12)) * 0x100000001b3 ^
                 (ulonglong)*(byte *)((longlong)plVar9 + 0x13)) * 0x100000001b3 & DAT_140013c20;
        plVar3 = *(longlong **)(DAT_140013c08 + uVar11 * 0x10);
        puVar1 = (undefined8 *)(DAT_140013c08 + uVar11 * 0x10);
        lVar12 = DAT_140013c08 + uVar11 * 0x10;
        if (plVar3 != plVar10) break;
        *puVar1 = plVar9;
        *(longlong **)(lVar12 + 8) = plVar9;
        plVar9 = plVar2;
      }
      plVar4 = *(longlong **)(lVar12 + 8);
      if ((int)plVar9[2] != (int)plVar4[2]) break;
      plVar4 = (longlong *)*plVar4;
      if (plVar4 != plVar9) {
        puVar1 = (undefined8 *)plVar9[1];
        *puVar1 = plVar2;
        puVar5 = (undefined8 *)plVar2[1];
        *puVar5 = plVar4;
        puVar6 = (undefined8 *)plVar4[1];
        *puVar6 = plVar9;
        plVar4[1] = (longlong)puVar5;
        plVar2[1] = (longlong)puVar1;
        plVar9[1] = (longlong)puVar6;
      }
      *(longlong **)(lVar12 + 8) = plVar9;
      plVar9 = plVar2;
    }
    do {
      if (plVar3 == plVar4) {
        puVar5 = (undefined8 *)plVar9[1];
        *puVar5 = plVar2;
        puVar6 = (undefined8 *)plVar2[1];
        *puVar6 = plVar4;
        puVar7 = (undefined8 *)plVar4[1];
        *puVar7 = plVar9;
        plVar4[1] = (longlong)puVar6;
        plVar2[1] = (longlong)puVar5;
        plVar9[1] = (longlong)puVar7;
        *puVar1 = plVar9;
        plVar9 = plVar2;
        goto joined_r0x00014000e772;
      }
      plVar4 = (longlong *)plVar4[1];
    } while ((int)plVar9[2] != (int)plVar4[2]);
    lVar12 = *plVar4;
    puVar1 = (undefined8 *)plVar9[1];
    *puVar1 = plVar2;
    plVar3 = (longlong *)plVar2[1];
    *plVar3 = lVar12;
    puVar5 = *(undefined8 **)(lVar12 + 8);
    *puVar5 = plVar9;
    *(longlong **)(lVar12 + 8) = plVar3;
    plVar2[1] = (longlong)puVar1;
    plVar9[1] = (longlong)puVar5;
    plVar9 = plVar2;
  } while( true );
}


void FUN_14000e8e0(longlong param_1)

{
  if ((param_1 == DAT_140013040) && ((short)((ulonglong)param_1 >> 0x30) == 0)) {
    return;
  }
  FUN_14000ef14();
  return;
}


void FUN_14000e96c(int *param_1)

{
  AcquireSRWLockExclusive((PSRWLOCK)&DAT_140013178);
  do {
    if (*param_1 == 0) {
      *param_1 = -1;
LAB_14000e9d4:
                    /* WARNING: Could not recover jumptable at 0x00014000e9e0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      ReleaseSRWLockExclusive((PSRWLOCK)&DAT_140013178);
      return;
    }
    if (*param_1 != -1) {
      *(undefined4 *)
       (*(longlong *)((longlong)ThreadLocalStoragePointer + (ulonglong)_tls_index * 8) + 4) =
           DAT_140013000;
      goto LAB_14000e9d4;
    }
    SleepConditionVariableSRW
              ((PCONDITION_VARIABLE)&DAT_140013170,(PSRWLOCK)&DAT_140013178,0xffffffff,0);
  } while( true );
}


longlong FUN_14000ea60(int param_1)

{
  char cVar1;
  uint7 extraout_var;
  uint7 uVar2;
  undefined7 extraout_var_00;
  uint7 extraout_var_01;
  
  if (param_1 == 0) {
    DAT_140013190 = 1;
  }
  FUN_14000ef60();
  cVar1 = FUN_14000f3b0();
  uVar2 = extraout_var;
  if (cVar1 != '\0') {
    cVar1 = FUN_14000f3b0();
    if (cVar1 != '\0') {
      return CONCAT71(extraout_var_00,1);
    }
    FUN_14000f3b0();
    uVar2 = extraout_var_01;
  }
  return (ulonglong)uVar2 << 8;
}


/* WARNING: Removing unreachable block (ram,0x00014000ebb5) */
/* WARNING: Enum "SectionFlags": Some values do not have unique names */

ulonglong FUN_14000eb28(longlong param_1)

{
  ulonglong uVar1;
  uint7 uVar2;
  IMAGE_SECTION_HEADER *pIVar3;
  
  uVar1 = 0;
  for (pIVar3 = &IMAGE_SECTION_HEADER_140000200; pIVar3 != (IMAGE_SECTION_HEADER *)&DAT_1400002c8;
      pIVar3 = pIVar3 + 1) {
    if (((ulonglong)(uint)pIVar3->VirtualAddress <= param_1 - 0x140000000U) &&
       (uVar1 = (ulonglong)((pIVar3->Misc).PhysicalAddress + pIVar3->VirtualAddress),
       param_1 - 0x140000000U < uVar1)) goto LAB_14000eb9e;
  }
  pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_14000eb9e:
  if (pIVar3 == (IMAGE_SECTION_HEADER *)0x0) {
    uVar1 = uVar1 & 0xffffffffffffff00;
  }
  else {
    uVar2 = (uint7)(uVar1 >> 8);
    if ((int)pIVar3->Characteristics < 0) {
      uVar1 = (ulonglong)uVar2 << 8;
    }
    else {
      uVar1 = CONCAT71(uVar2,1);
    }
  }
  return uVar1;
}


undefined8 * FUN_14000ec74(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = type_info::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}


void FUN_14000eca0(void)

{
  code *pcVar1;
  bool bVar2;
  char cVar3;
  int iVar4;
  undefined8 uVar5;
  undefined4 *puVar6;
  ulonglong uVar7;
  undefined7 extraout_var;
  
  _set_app_type(1);
  uVar5 = FUN_14000f398();
  _set_fmode((int)uVar5);
  uVar5 = FUN_14000f220();
  puVar6 = (undefined4 *)__p__commode();
  *puVar6 = (int)uVar5;
  uVar5 = __scrt_initialize_onexit_tables(1);
  if ((char)uVar5 != '\0') {
    FUN_14000f3fc();
    atexit((_func_5014 *)&LAB_14000f438);
    uVar7 = FUN_14000f1fc();
    iVar4 = _configure_narrow_argv(uVar7 & 0xffffffff);
    if (iVar4 == 0) {
      FUN_14000f3a0();
      bVar2 = FUN_14000f3e0();
      if ((int)CONCAT71(extraout_var,bVar2) != 0) {
        __setusermatherr(FUN_14000f220);
      }
      _guard_check_icall();
      _guard_check_icall();
      uVar5 = FUN_14000f220();
      _configthreadlocale((int)uVar5);
      cVar3 = FUN_14000f3b0();
      if (cVar3 != '\0') {
        _initialize_narrow_environment();
      }
      FUN_14000f220();
      uVar5 = thunk_FUN_14000f220();
      if ((int)uVar5 == 0) {
        return;
      }
    }
  }
  FUN_14000f210(7);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}


undefined8 FUN_14000ed58(void)

{
  FUN_14000f3c4();
  return 0;
}


/* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */

int FUN_14000ed84(void)

{
  bool bVar1;
  bool bVar2;
  int iVar3;
  undefined8 uVar4;
  longlong *plVar5;
  ulonglong uVar6;
  uint *puVar7;
  undefined8 unaff_RBX;
  undefined8 in_R9;
  undefined1 uVar8;
  
  iVar3 = (int)unaff_RBX;
  uVar4 = FUN_14000ea60(1);
  if ((char)uVar4 == '\0') {
    FUN_14000f210(7);
  }
  else {
    bVar1 = false;
    uVar8 = 0;
    uVar4 = __scrt_acquire_startup_lock();
    iVar3 = (int)CONCAT71((int7)((ulonglong)unaff_RBX >> 8),(char)uVar4);
    if (DAT_140013180 != 1) {
      if (DAT_140013180 == 0) {
        DAT_140013180 = 1;
        iVar3 = _initterm_e(&DAT_140010330,&DAT_140010348);
        if (iVar3 != 0) {
          return 0xff;
        }
        _initterm(&DAT_1400102d8,&DAT_140010328);
        DAT_140013180 = 2;
      }
      else {
        bVar1 = true;
        uVar8 = 1;
      }
      __scrt_release_startup_lock((char)uVar4);
      plVar5 = (longlong *)FUN_14000f3ec();
      if ((*plVar5 != 0) && (uVar6 = FUN_14000eb28((longlong)plVar5), (char)uVar6 != '\0')) {
        (*(code *)*plVar5)(0,2,0,in_R9,uVar8);
      }
      plVar5 = (longlong *)FUN_14000f3f4();
      if ((*plVar5 != 0) && (uVar6 = FUN_14000eb28((longlong)plVar5), (char)uVar6 != '\0')) {
        _register_thread_local_exe_atexit_callback(*plVar5);
      }
      _get_initial_narrow_environment();
      __p___argv();
      puVar7 = (uint *)__p___argc();
      uVar6 = (ulonglong)*puVar7;
      iVar3 = FUN_140003890();
      bVar2 = FUN_14000f224();
      if (bVar2) {
        if (!bVar1) {
          _cexit();
        }
        __scrt_uninitialize_crt(CONCAT71((int7)(uVar6 >> 8),1),'\0');
        return iVar3;
      }
      goto LAB_14000eef0;
    }
  }
  FUN_14000f210(7);
LAB_14000eef0:
                    /* WARNING: Subroutine does not return */
  exit(iVar3);
}


void FUN_14000ef14(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)swi(0x29);
  (*pcVar1)(2);
  return;
}


undefined8 * FUN_14000ef1c(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad allocation";
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}


void FUN_14000ef40(void)

{
  undefined8 local_28 [5];
  
  FUN_14000ef1c(local_28);
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_140011640);
}


/* WARNING: Removing unreachable block (ram,0x00014000f04b) */
/* WARNING: Removing unreachable block (ram,0x00014000f03b) */
/* WARNING: Removing unreachable block (ram,0x00014000f016) */
/* WARNING: Removing unreachable block (ram,0x00014000ef9a) */
/* WARNING: Removing unreachable block (ram,0x00014000ef78) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 FUN_14000ef60(void)

{
  int *piVar1;
  uint *puVar2;
  int *piVar3;
  longlong lVar4;
  uint uVar5;
  byte bVar6;
  ulonglong uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint in_XCR0;
  
  piVar1 = (int *)cpuid_basic_info(0);
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar5 = puVar2[3];
  if ((piVar1[2] == 0x49656e69 && piVar1[3] == 0x6c65746e) && piVar1[1] == 0x756e6547) {
    uVar8 = *puVar2 & 0xfff3ff0;
    _DAT_140013090 = 0x8000;
    _DAT_140013098 = 0xffffffffffffffff;
    if ((((uVar8 == 0x106c0) || (uVar8 == 0x20660)) || (uVar8 == 0x20670)) ||
       ((uVar8 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar8 - 0x30650) & 0x3f) & 1) != 0)))) {
      DAT_1400131cc = DAT_1400131cc | 1;
    }
  }
  uVar10 = 0;
  uVar8 = 0;
  if (*piVar1 < 7) {
    uVar11 = 0;
    uVar9 = 0;
  }
  else {
    piVar3 = (int *)cpuid_Extended_Feature_Enumeration_info(7);
    uVar11 = piVar3[1];
    uVar9 = piVar3[2];
    if ((uVar11 >> 9 & 1) != 0) {
      DAT_1400131cc = DAT_1400131cc | 2;
    }
    if (0 < *piVar3) {
      lVar4 = cpuid_Extended_Feature_Enumeration_info(7);
      uVar10 = *(uint *)(lVar4 + 8);
    }
    if (0x23 < *piVar1) {
      lVar4 = cpuid(0x24);
      uVar8 = *(uint *)(lVar4 + 4);
    }
  }
  _DAT_140013088 = 1;
  DAT_14001308c = 2;
  uVar7 = DAT_1400130a0 & 0xfffffffffffffffe;
  if ((uVar5 >> 0x14 & 1) != 0) {
    _DAT_140013088 = 2;
    DAT_14001308c = 6;
    uVar7 = DAT_1400130a0 & 0xffffffffffffffee;
  }
  DAT_1400130a0 = uVar7;
  if ((uVar5 >> 0x1b & 1) != 0) {
    if (((uVar5 >> 0x1c & 1) != 0) && (bVar6 = (byte)in_XCR0, (bVar6 & 6) == 6)) {
      _DAT_140013088 = 3;
      uVar5 = DAT_14001308c | 8;
      uVar7 = DAT_1400130a0;
      if ((uVar11 & 0x20) != 0) {
        _DAT_140013088 = 5;
        uVar5 = DAT_14001308c | 0x28;
        uVar7 = DAT_1400130a0 & 0xfffffffffffffffd;
        if (((uVar11 & 0xd0030000) == 0xd0030000) && ((bVar6 & 0xe0) == 0xe0)) {
          DAT_14001308c = DAT_14001308c | 0x68;
          _DAT_140013088 = 6;
          uVar5 = DAT_14001308c;
          uVar7 = DAT_1400130a0 & 0xffffffffffffffd9;
        }
      }
      DAT_1400130a0 = uVar7;
      DAT_14001308c = uVar5;
      if ((uVar9 >> 0x17 & 1) != 0) {
        DAT_1400130a0 = DAT_1400130a0 & 0xfffffffffeffffff;
      }
      if (((uVar10 >> 0x13 & 1) != 0) && ((bVar6 & 0xe0) == 0xe0)) {
        _DAT_1400131d0 = uVar8 & 0x400ff;
        DAT_1400130a0 = DAT_1400130a0 & ~((ulonglong)(uVar8 >> 0x10 & 6) | 0x1000029);
        if (1 < (byte)_DAT_1400131d0) {
          DAT_1400130a0 = DAT_1400130a0 & 0xffffffffffffffbf;
        }
      }
    }
    if (((uVar10 >> 0x15 & 1) != 0) && ((in_XCR0 >> 0x13 & 1) != 0)) {
      DAT_1400130a0 = DAT_1400130a0 & 0xffffffffffffff7f;
    }
  }
  return 0;
}


undefined8 FUN_14000f1fc(void)

{
  return 1;
}


void FUN_14000f210(undefined4 param_1)

{
  code *pcVar1;
  
  pcVar1 = (code *)swi(0x29);
  (*pcVar1)(param_1);
  return;
}


undefined8 FUN_14000f220(void)

{
  return 0;
}


bool FUN_14000f224(void)

{
  HMODULE pHVar1;
  longlong lVar2;
  bool bVar3;
  
  pHVar1 = GetModuleHandleW((LPCWSTR)0x0);
  if ((((pHVar1 == (HMODULE)0x0) || ((short)pHVar1->unused != 0x5a4d)) ||
      (lVar2 = (longlong)pHVar1[0xf].unused, *(int *)((longlong)&pHVar1->unused + lVar2) != 0x4550))
     || ((*(short *)((longlong)&pHVar1[6].unused + lVar2) != 0x20b ||
         (*(uint *)((longlong)&pHVar1[0x21].unused + lVar2) < 0xf)))) {
    bVar3 = false;
  }
  else {
    bVar3 = *(int *)((longlong)&pHVar1[0x3e].unused + lVar2) != 0;
  }
  return bVar3;
}


void FUN_14000f278(void)

{
                    /* WARNING: Could not recover jumptable at 0x00014000f27f. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  SetUnhandledExceptionFilter(&LAB_14000f288);
  return;
}


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_14000f2e8(void)

{
  DWORD DVar1;
  _FILETIME local_res8;
  LARGE_INTEGER local_res10;
  _FILETIME local_18 [2];
  
  if (DAT_140013040 == 0x2b992ddfa232) {
    local_res8.dwLowDateTime = 0;
    local_res8.dwHighDateTime = 0;
    GetSystemTimeAsFileTime(&local_res8);
    local_18[0] = local_res8;
    DVar1 = GetCurrentThreadId();
    local_18[0] = (_FILETIME)((ulonglong)local_18[0] ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_18[0] = (_FILETIME)((ulonglong)local_18[0] ^ (ulonglong)DVar1);
    QueryPerformanceCounter(&local_res10);
    DAT_140013040 =
         ((ulonglong)local_res10.s.LowPart << 0x20 ^
          CONCAT44(local_res10.s.HighPart,local_res10.s.LowPart) ^ (ulonglong)local_18[0] ^
         (ulonglong)local_18) & 0xffffffffffff;
    if (DAT_140013040 == 0x2b992ddfa232) {
      DAT_140013040 = 0x2b992ddfa233;
    }
  }
  _DAT_140013080 = ~DAT_140013040;
  return;
}


undefined8 FUN_14000f398(void)

{
  return 0x4000;
}


void FUN_14000f3a0(void)

{
                    /* WARNING: Could not recover jumptable at 0x00014000f3a7. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  InitializeSListHead(&DAT_1400131e0);
  return;
}


undefined1 FUN_14000f3b0(void)

{
  return 1;
}


undefined * FUN_14000f3b4(void)

{
  return &DAT_1400131f0;
}


undefined * FUN_14000f3bc(void)

{
  return &DAT_1400131f8;
}


void FUN_14000f3c4(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_14000f3b4();
  *puVar1 = *puVar1 | 0x24;
  puVar1 = (ulonglong *)FUN_14000f3bc();
  *puVar1 = *puVar1 | 2;
  return;
}


bool FUN_14000f3e0(void)

{
  return DAT_1400130a8 == 0;
}


undefined * FUN_14000f3ec(void)

{
  return &DAT_140013c60;
}


undefined * FUN_14000f3f4(void)

{
  return &DAT_140013c58;
}


/* WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall */

void FUN_14000f3fc(void)

{
  undefined8 *puVar1;
  
  for (puVar1 = &DAT_140010ff0; puVar1 < &DAT_140010ff0; puVar1 = puVar1 + 1) {
    if ((code *)*puVar1 != (code *)0x0) {
      (*(code *)*puVar1)();
    }
  }
  return;
}


void FUN_14000f568(ulonglong param_1,longlong param_2,uint *param_3)

{
  ulonglong uVar1;
  ulonglong uVar2;
  
  uVar2 = param_1;
  if ((*param_3 & 4) != 0) {
    uVar2 = (longlong)(int)param_3[1] + param_1 & (longlong)(int)-param_3[2];
  }
  uVar1 = (ulonglong)*(uint *)(*(longlong *)(param_2 + 0x10) + 8);
  if ((*(byte *)(uVar1 + 3 + *(longlong *)(param_2 + 8)) & 0xf) != 0) {
    param_1 = ((ulonglong)*(byte *)(uVar1 + 3 + *(longlong *)(param_2 + 8)) & 0xfffffff0) + param_1;
  }
  FUN_14000e8e0(*(ulonglong *)((longlong)(int)(*param_3 & 0xfffffff8) + uVar2) ^ param_1);
  return;
}


void FUN_14000f830(undefined8 *param_1)

{
  _seh_filter_exe(*(undefined4 *)*param_1,param_1);
  return;
}


/* Library Function - Single Match
    void * __ptr64 __cdecl operator new(unsigned __int64)
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */

void * __cdecl operator_new(__uint64 param_1)

{
  code *pcVar1;
  int iVar2;
  void *pvVar3;
  
  do {
    pvVar3 = malloc(param_1);
    if (pvVar3 != (void *)0x0) {
      return pvVar3;
    }
    iVar2 = _callnewh(param_1);
  } while (iVar2 != 0);
  if (param_1 == 0xffffffffffffffff) {
    FUN_140001440();
    pcVar1 = (code *)swi(3);
    pvVar3 = (void *)(*pcVar1)();
    return pvVar3;
  }
  FUN_14000ef40();
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_140003890(void)

{
  longlong lVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  byte ****ppppbVar4;
  code *pcVar5;
  undefined1 auVar6 [16];
  undefined1 auVar7 [16];
  undefined1 auVar8 [16];
  undefined1 auVar9 [16];
  undefined1 auVar10 [16];
  undefined1 auVar11 [16];
  undefined1 auVar12 [16];
  longlong *plVar13;
  size_t sVar14;
  char cVar15;
  byte bVar16;
  uint uVar17;
  byte *pbVar18;
  ulonglong uVar19;
  void *pvVar20;
  longlong *plVar21;
  byte *pbVar22;
  void *pvVar23;
  basic_ostream<> *pbVar24;
  byte *****pppppbVar25;
  byte *pbVar26;
  byte ****_Memory;
  longlong lVar27;
  byte bVar28;
  byte bVar29;
  longlong lVar30;
  ulonglong uVar31;
  char *_Memory_00;
  char *****pppppcVar32;
  byte bVar33;
  int iVar34;
  longlong lVar35;
  byte *****pppppbVar36;
  byte *****pppppbVar37;
  undefined1 *puVar38;
  ulonglong uVar39;
  undefined1 *puVar40;
  int *piVar41;
  ulonglong uVar42;
  ulonglong uVar43;
  ulonglong uVar44;
  ulonglong uVar45;
  ulonglong uVar46;
  ulonglong uVar47;
  byte *pbVar48;
  code *pcVar49;
  bool bVar50;
  undefined8 uStack_4f0;
  undefined1 auStack_4e8 [8];
  undefined1 auStack_4e0 [24];
  undefined8 local_4c8;
  ulonglong local_4c0;
  ulonglong local_4b8 [2];
  byte local_4a8;
  longlong local_4a0 [7];
  byte *local_468;
  byte *local_460;
  byte *local_458;
  byte *local_450;
  byte *local_448;
  byte *local_440;
  byte *local_438;
  byte *local_430;
  byte *local_428;
  byte *local_420;
  byte *local_418;
  byte *local_410;
  byte *local_408;
  byte *local_400;
  byte *local_3f8;
  byte *local_3f0;
  byte *local_3e8;
  byte *local_3e0;
  byte *local_3d8;
  byte *local_3d0;
  byte *local_3c8;
  byte *local_3c0;
  byte *local_3b8;
  byte *local_3b0;
  byte *local_3a8;
  byte *local_3a0;
  byte *local_398;
  byte *local_390;
  byte *local_388;
  byte *local_380;
  byte *local_378;
  byte *local_370;
  byte *local_368;
  byte *local_360;
  byte *local_358;
  byte *local_350;
  byte *local_348;
  byte *local_340;
  byte *local_338;
  byte *local_330;
  byte *local_328;
  byte *local_320;
  byte *local_318;
  byte *local_310;
  byte *local_308;
  byte *local_300;
  byte *local_2f8;
  byte *local_2f0;
  byte *local_2e8;
  byte *local_2e0;
  byte *local_2d8;
  byte *local_2d0;
  byte *local_2c8;
  byte *local_2c0;
  byte *local_2b8;
  byte *local_2b0;
  byte *local_2a8;
  byte *local_2a0;
  byte *local_298;
  byte *local_290;
  byte *local_288;
  byte *local_280;
  byte *local_278;
  byte *local_270;
  byte *local_268;
  byte *local_260;
  byte *local_258;
  byte *local_250;
  byte *local_248;
  byte *local_240;
  byte *local_238;
  byte *local_230;
  byte *local_228;
  byte *local_220;
  byte *local_218;
  byte *local_210;
  byte *local_208;
  byte *local_200;
  byte *local_1f8;
  byte *local_1f0;
  byte *local_1e8;
  basic_ostream<> *local_1e0;
  int *local_1d8;
  void *local_1d0;
  undefined8 uStack_1c8;
  longlong local_1c0;
  ulonglong local_1b8;
  char *local_198;
  undefined8 local_190;
  undefined8 local_188;
  ulonglong local_180;
  longlong local_160 [7];
  byte ****local_128;
  undefined8 uStack_120;
  byte ****local_118;
  ulonglong local_110;
  ulonglong local_108;
  char local_100;
  undefined1 local_f8;
  undefined7 uStack_f7;
  byte *local_e8;
  ulonglong local_e0;
  byte ****local_d8;
  undefined8 uStack_d0;
  size_t local_c8;
  ulonglong local_c0;
  byte ****local_b8;
  undefined8 uStack_b0;
  ulonglong local_a8;
  ulonglong local_a0;
  ulonglong local_98;
  char local_90;
  char ****local_88;
  undefined8 uStack_80;
  ulonglong local_78;
  ulonglong local_70;
  ulonglong local_50;
  
  puVar40 = auStack_4e8;
  local_50 = DAT_140013040 ^ (ulonglong)auStack_4e8;
  uStack_120 = 0;
  local_118 = (byte ****)0x0;
  local_110 = 0xf;
  local_128 = (byte ****)0x0;
  if (DAT_140013218 == '\0') {
    DAT_140013210 = FUN_140003760;
    DAT_140013218 = '\x01';
  }
  pbVar18 = (byte *)FUN_14000d620(&local_198,"");
  uVar39 = DAT_140013be0;
  uVar43 = *(ulonglong *)(pbVar18 + 0x10);
  pbVar26 = pbVar18;
  if (0xf < *(ulonglong *)(pbVar18 + 0x18)) {
    pbVar26 = *(byte **)pbVar18;
  }
  pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
  if (DAT_14001321a == '\0') {
    lVar30 = 0;
    do {
      (&DAT_1400133d0)[lVar30] = ~DAT_1400130b8 ^ (ulonglong)pbVar48 ^ uVar39;
      DAT_1400130b8 = DAT_1400130b8 - 0xffffffff;
      lVar30 = lVar30 + 1;
    } while (lVar30 != 0x100);
    DAT_14001321a = '\x01';
  }
  iVar34 = 0;
  if (uVar43 != 0) {
    do {
      bVar16 = pbVar26[iVar34];
      local_4c8._1_1_ = (byte)(uVar39 >> 8);
      local_4c8._0_2_ = CONCAT11(local_4c8._1_1_ ^ bVar16,(byte)uVar39 ^ bVar16);
      local_4c8._2_1_ = (byte)(uVar39 >> 0x10);
      local_4c8._0_3_ = CONCAT12(local_4c8._2_1_ ^ bVar16,(undefined2)local_4c8);
      local_4c8._3_1_ = (byte)(uVar39 >> 0x18);
      local_4c8._0_4_ = CONCAT13(local_4c8._3_1_ ^ bVar16,(undefined3)local_4c8);
      local_4c8._4_1_ = (byte)(uVar39 >> 0x20);
      local_4c8._0_5_ = CONCAT14(local_4c8._4_1_ ^ bVar16,(undefined4)local_4c8);
      local_4c8._5_1_ = (byte)(uVar39 >> 0x28);
      local_4c8._0_6_ = CONCAT15(local_4c8._5_1_ ^ bVar16,(undefined5)local_4c8);
      local_4c8._6_1_ = (byte)(uVar39 >> 0x30);
      local_4c8._7_1_ = (byte)(uVar39 >> 0x38);
      local_4c8._0_7_ = CONCAT16(local_4c8._6_1_ ^ bVar16,(undefined6)local_4c8);
      local_4c8 = CONCAT17(local_4c8._7_1_ ^ bVar16,(undefined7)local_4c8);
      uVar39 = local_4c8 ^ (&DAT_1400133d0)[(byte)~bVar16];
      iVar34 = iVar34 + 1;
    } while ((ulonglong)(longlong)iVar34 < uVar43);
  }
                    /* WARNING: Load size is inaccurate */
  piVar41 = (int *)(*ThreadLocalStoragePointer + 4);
  local_4c8 = uVar39;
  local_1d8 = piVar41;
  if (*piVar41 < DAT_140013c50) {
    FUN_14000e96c(&DAT_140013c50);
    if (DAT_140013c50 == -1) {
      _DAT_140013c48 = uVar39;
      _Init_thread_footer(&DAT_140013c50);
    }
    pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
  }
  if (*piVar41 < DAT_140013c40) {
    FUN_14000e96c(&DAT_140013c40);
    if (DAT_140013c40 == -1) {
      _DAT_140013c38 = CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
      _Init_thread_footer(&DAT_140013c40);
    }
    pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
  }
  uVar39 = local_4c8;
  local_4a8 = *pbVar26;
  bVar16 = DAT_140013bd0;
  if (1 < uVar43) {
    bVar16 = pbVar26[uVar43 - 1];
  }
  uVar17 = 0;
  bVar28 = (byte)uVar43;
  bVar33 = bVar28;
  do {
    bVar28 = bVar28 ^ local_4a8;
    bVar33 = bVar33 ^ bVar16;
    uVar17 = uVar17 + 1;
  } while (uVar17 < 8);
  local_4a0[0]._1_7_ = (undefined7)(uVar43 >> 8);
  local_4a0[0] = CONCAT71(local_4a0[0]._1_7_,bVar28);
  local_4b8[0] = CONCAT71(local_4a0[0]._1_7_,bVar33);
  uVar31 = uVar43 * 8;
  bVar50 = DAT_140013200 == '\0';
  _DAT_140013c38 = uVar43 ^ (ulonglong)pbVar48 ^ _DAT_140013c38;
  uVar46 = local_4a0[0];
  if (bVar50) {
    uVar46 = local_4b8[0];
  }
  uVar44 = local_4c8 >> 0x28;
  uVar42 = _DAT_140013c38 ^ uVar43 ^ (ulonglong)pbVar48;
  local_4c8._0_2_ =
       CONCAT11((byte)(uVar42 >> 8) ^ (byte)(local_4c8 >> 8),(byte)local_4c8 ^ (byte)_DAT_140013c38)
  ;
  uVar19 = local_4a0[0];
  if (!bVar50) {
    uVar19 = local_4b8[0];
  }
  bVar33 = (byte)uVar31;
  uVar47 = uVar43 << (bVar33 & 0xf) ^ uVar42 ^ (ulonglong)pbVar48;
  local_4c8._0_3_ = CONCAT12((byte)(uVar47 >> 0x10) ^ (byte)(uVar39 >> 0x10),(undefined2)local_4c8);
  uVar42 = local_4a0[0];
  if (bVar50) {
    uVar42 = local_4b8[0];
  }
  uVar45 = uVar43 << (bVar33 + (char)(uVar31 / 0x18) * -0x18 & 0x3f) ^ uVar47 ^ (ulonglong)pbVar48;
  local_4c8._0_4_ = CONCAT13((byte)(uVar45 >> 0x18) ^ (byte)(uVar39 >> 0x18),(undefined3)local_4c8);
  uVar47 = local_4a0[0];
  if (!bVar50) {
    uVar47 = local_4b8[0];
  }
  local_4c8._5_3_ =
       (uint3)uVar44 ^ (uint3)((uVar46 << 0x38) >> 0x28) ^ (uint3)((uVar19 << 0x38) >> 0x28) ^
       (uint3)((uVar42 << 0x30) >> 0x28) ^ (uint3)uVar47;
  uVar45 = uVar43 << (bVar33 & 0x1f) ^ uVar45 ^ (ulonglong)pbVar48;
  local_4c8._0_5_ = CONCAT14((byte)(uVar45 >> 0x20) ^ (byte)(uVar39 >> 0x20),(undefined4)local_4c8);
  uVar39 = local_4a0[0];
  if (bVar50) {
    uVar39 = local_4b8[0];
  }
  uVar39 = local_4c8 ^ uVar39 << 0x20;
  uVar46 = uVar43 << (bVar33 + (char)(uVar31 / 0x28) * -0x28 & 0x3f) ^ uVar45 ^ (ulonglong)pbVar48;
  local_4c8._6_2_ = (undefined2)(uVar39 >> 0x30);
  local_4c8._0_5_ = (undefined5)uVar39;
  local_4c8._0_6_ = CONCAT15((byte)(uVar46 >> 0x28) ^ (byte)(uVar39 >> 0x28),(undefined5)local_4c8);
  uVar39 = local_4a0[0];
  if (!bVar50) {
    uVar39 = local_4b8[0];
  }
  uVar39 = local_4c8 ^ uVar39 << 0x18;
  uVar46 = uVar43 << (bVar33 + (char)(uVar31 / 0x30) * -0x30 & 0x3f) ^ uVar46 ^ (ulonglong)pbVar48;
  local_4c8._7_1_ = (byte)(uVar39 >> 0x38);
  local_4c8._0_6_ = (undefined6)uVar39;
  local_4c8._0_7_ = CONCAT16((byte)(uVar46 >> 0x30) ^ (byte)(uVar39 >> 0x30),(undefined6)local_4c8);
  uVar39 = local_4a0[0];
  if (bVar50) {
    uVar39 = local_4b8[0];
  }
  local_4c8 = local_4c8 ^ uVar39 << 0x10;
  auVar6._8_8_ = 0;
  auVar6._0_8_ = uVar31;
  lVar30 = SUB168(ZEXT816(0x2492492492492493) * auVar6,8);
  local_4c8 = CONCAT17((byte)((uVar43 <<
                              (bVar33 + (char)((uVar31 - lVar30 >> 1) + lVar30 >> 5) * -0x38 & 0x3f)
                              ) >> 0x38) ^ (byte)(uVar46 >> 0x38) ^ (byte)(local_4c8 >> 0x38) ^
                       DAT_140013be8._7_1_,(undefined7)local_4c8);
  uVar43 = local_4a0[0];
  if (!bVar50) {
    uVar43 = local_4b8[0];
  }
  local_108 = DAT_140013bd8 + (ulonglong)bVar16 * -0xff + (ulonglong)local_4a8 * -0x80 ^ uVar43 << 8
              ^ local_4c8 ^ _DAT_140013c48;
  uVar43 = 0;
  _DAT_140013c48 = 0;
  _DAT_140013c38 = 0;
  DAT_140013200 = '\0';
  FUN_14000d5f0((longlong *)&local_128,(longlong *)pbVar18);
  if (0xf < *(ulonglong *)(pbVar18 + 0x18)) {
    pvVar23 = *(void **)pbVar18;
    pvVar20 = pvVar23;
    puVar40 = auStack_4e8;
    if ((0xfff < *(ulonglong *)(pbVar18 + 0x18) + 1) &&
       (pvVar20 = *(void **)((longlong)pvVar23 + -8), puVar40 = auStack_4e8,
       0x1f < (ulonglong)((longlong)pvVar23 + (-8 - (longlong)pvVar20)))) {
      pcVar49 = (code *)swi(0x29);
      pvVar20 = (void *)(*pcVar49)(5);
      puVar40 = auStack_4e0;
    }
    *(undefined8 *)(puVar40 + -8) = 0x140003dc1;
    free(pvVar20);
  }
  pbVar18[0x10] = 0;
  pbVar18[0x11] = 0;
  pbVar18[0x12] = 0;
  pbVar18[0x13] = 0;
  pbVar18[0x14] = 0;
  pbVar18[0x15] = 0;
  pbVar18[0x16] = 0;
  pbVar18[0x17] = 0;
  pbVar18[0x18] = 0xf;
  pbVar18[0x19] = 0;
  pbVar18[0x1a] = 0;
  pbVar18[0x1b] = 0;
  pbVar18[0x1c] = 0;
  pbVar18[0x1d] = 0;
  pbVar18[0x1e] = 0;
  pbVar18[0x1f] = 0;
  *pbVar18 = 0;
  if ((DAT_14001321b == '\0') && (DAT_140013218 == '\0')) {
    DAT_140013210 = FUN_140003760;
    DAT_140013218 = '\x01';
    DAT_14001321b = '\x01';
  }
  *(undefined8 *)(puVar40 + -8) = 0x140003e14;
  plVar21 = FUN_14000d620(&local_198,
                          "Hello kind traveler! I have something you seek. But first i need somethin g in return. \n Could you remind me what year it is? All this time spent h ere, and I\'ve forgotten :("
                         );
  *(longlong **)(puVar40 + 0x28) = plVar21;
  local_100 = '\x01';
  *(undefined8 *)(puVar40 + -8) = 0x140003e32;
  FUN_14000d5f0((longlong *)&local_128,plVar21);
  ppppbVar4 = local_118;
  piVar41 = local_1d8;
  uVar39 = DAT_140013be0;
  if (local_100 == '\0') {
    pppppbVar25 = &local_128;
    if (0xf < local_110) {
      pppppbVar25 = (byte *****)local_128;
    }
    pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    uVar31 = uVar43;
    if (DAT_14001321a == '\0') {
      do {
        (&DAT_1400133d0)[uVar31] = ~DAT_1400130b8 ^ (ulonglong)pbVar48 ^ uVar39;
        DAT_1400130b8 = DAT_1400130b8 - 0xffffffff;
        uVar31 = uVar31 + 1;
      } while (uVar31 != 0x100);
      DAT_14001321a = '\x01';
    }
    *(ulonglong *)(puVar40 + 0x20) = uVar39;
    if ((byte *****)local_118 != (byte *****)0x0) {
      do {
        bVar16 = *(byte *)((longlong)pppppbVar25 + (longlong)(int)uVar43);
        puVar40[0x20] = (byte)uVar39 ^ bVar16;
        puVar40[0x21] = puVar40[0x21] ^ bVar16;
        puVar40[0x22] = puVar40[0x22] ^ bVar16;
        puVar40[0x23] = puVar40[0x23] ^ bVar16;
        puVar40[0x24] = puVar40[0x24] ^ bVar16;
        puVar40[0x25] = puVar40[0x25] ^ bVar16;
        puVar40[0x26] = puVar40[0x26] ^ bVar16;
        puVar40[0x27] = puVar40[0x27] ^ bVar16;
        uVar39 = *(ulonglong *)(puVar40 + 0x20) ^ (&DAT_1400133d0)[(byte)~bVar16];
        *(ulonglong *)(puVar40 + 0x20) = uVar39;
        uVar17 = (int)uVar43 + 1;
        uVar43 = (ulonglong)uVar17;
      } while ((byte *****)(longlong)(int)uVar17 < local_118);
    }
    if (*local_1d8 < DAT_140013c50) {
      *(undefined8 *)(puVar40 + -8) = 0x140003f37;
      FUN_14000e96c(&DAT_140013c50);
      if (DAT_140013c50 == -1) {
        *(undefined8 *)(puVar40 + -8) = 0x140003f53;
        _DAT_140013c48 = uVar39;
        _Init_thread_footer(&DAT_140013c50);
      }
      pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    }
    if (*piVar41 < DAT_140013c40) {
      *(undefined8 *)(puVar40 + -8) = 0x140003f70;
      FUN_14000e96c(&DAT_140013c40);
      if (DAT_140013c40 == -1) {
        _DAT_140013c38 = CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
        *(undefined8 *)(puVar40 + -8) = 0x140003f93;
        _Init_thread_footer(&DAT_140013c40);
      }
      pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    }
    pcVar49 = DAT_140013210;
    bVar16 = *(byte *)pppppbVar25;
    bVar33 = DAT_140013bd0;
    if ((byte *****)0x1 < ppppbVar4) {
      bVar33 = ((byte *)((longlong)ppppbVar4 + -1))[(longlong)pppppbVar25];
    }
    *(byte *****)(puVar40 + 0x30) = ppppbVar4;
    *(byte *****)(puVar40 + 0x48) = ppppbVar4;
    uVar17 = 0;
    bVar29 = (byte)ppppbVar4;
    bVar28 = bVar29;
    do {
      bVar29 = bVar29 ^ bVar16;
      bVar28 = bVar28 ^ bVar33;
      uVar17 = uVar17 + 1;
    } while (uVar17 < 8);
    puVar40[0x30] = bVar29;
    puVar40[0x48] = bVar28;
    uVar43 = (longlong)ppppbVar4 * 8;
    bVar50 = DAT_140013200 == '\0';
    _DAT_140013c38 = (ulonglong)ppppbVar4 ^ (ulonglong)pbVar48 ^ _DAT_140013c38;
    puVar40[0x20] = puVar40[0x20] ^ (byte)_DAT_140013c38;
    lVar30 = *(longlong *)(puVar40 + 0x30);
    lVar1 = *(longlong *)(puVar40 + 0x48);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x38;
    uVar31 = (ulonglong)ppppbVar4 ^ _DAT_140013c38 ^ (ulonglong)pbVar48;
    puVar40[0x21] = (byte)(uVar39 >> 8) ^ (byte)(uVar31 >> 8);
    lVar27 = lVar30;
    if (!bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x38;
    bVar28 = (byte)uVar43;
    uVar31 = (longlong)ppppbVar4 << (bVar28 & 0xf) ^ (ulonglong)pbVar48 ^ uVar31;
    puVar40[0x22] = (byte)(uVar39 >> 0x10) ^ (byte)(uVar31 >> 0x10);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x30;
    uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x18) * -0x18 & 0x3f) ^
             (ulonglong)pbVar48 ^ uVar31;
    puVar40[0x23] = (byte)(uVar39 >> 0x18) ^ (byte)(uVar31 >> 0x18);
    lVar27 = lVar30;
    if (!bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x28;
    uVar31 = (longlong)ppppbVar4 << (bVar28 & 0x1f) ^ uVar31 ^ (ulonglong)pbVar48;
    puVar40[0x24] = (byte)(uVar31 >> 0x20) ^ (byte)(uVar39 >> 0x20);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x20;
    uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x28) * -0x28 & 0x3f) ^ uVar31 ^
             (ulonglong)pbVar48;
    puVar40[0x25] = (byte)(uVar31 >> 0x28) ^ (byte)((uVar39 ^ lVar27 << 0x20) >> 0x28);
    lVar27 = lVar30;
    if (!bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x18;
    uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x30) * -0x30 & 0x3f) ^ uVar31 ^
             (ulonglong)pbVar48;
    puVar40[0x26] = (byte)(uVar31 >> 0x30) ^ (byte)((uVar39 ^ lVar27 << 0x18) >> 0x30);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x10;
    auVar7._8_8_ = 0;
    auVar7._0_8_ = uVar43;
    lVar35 = SUB168(ZEXT816(0x2492492492492493) * auVar7,8);
    puVar40[0x27] =
         (byte)((ulonglong)
                ((longlong)ppppbVar4 <<
                (bVar28 + (char)((uVar43 - lVar35 >> 1) + lVar35 >> 5) * -0x38 & 0x3f)) >> 0x38) ^
         (byte)(uVar31 >> 0x38) ^ (byte)((uVar39 ^ lVar27 << 0x10) >> 0x38) ^ DAT_140013be8._7_1_;
    if (!bVar50) {
      lVar30 = lVar1;
    }
    uVar43 = DAT_140013bd8 + (ulonglong)bVar16 * -0x80 + (ulonglong)bVar33 * -0xff ^ lVar30 << 8 ^
             *(ulonglong *)(puVar40 + 0x20) ^ _DAT_140013c48;
    _DAT_140013c48 = 0;
    _DAT_140013c38 = 0;
    DAT_140013200 = '\0';
    if (uVar43 != local_108) {
      *(undefined8 *)(puVar40 + -8) = 0x1400042ae;
      plVar21 = FUN_140003640((longlong *)&local_88,local_108,uVar43);
      *(undefined8 *)(puVar40 + -8) = 0x1400042ba;
      (*pcVar49)(plVar21,&local_128);
    }
    plVar21 = *(longlong **)(puVar40 + 0x28);
  }
  pbVar18 = (byte *)0x0;
  *(undefined8 *)(puVar40 + -8) = 0x1400042d2;
  FUN_14000d740((undefined8 *)&local_f8,&local_128);
  pbVar26 = local_e8;
  local_1f0 = local_e8;
  local_100 = '\x01';
  pppppbVar25 = &local_128;
  if (0xf < local_110) {
    pppppbVar25 = (byte *****)local_128;
  }
  if (DAT_140013219 == '\0') {
    *(undefined8 *)(puVar40 + -8) = 0x14000430d;
    FUN_140001c90();
  }
  if ((pppppbVar25 != (byte *****)0x0) && (pbVar26 != (byte *)0x0)) {
    *(undefined8 *)(puVar40 + -8) = 0x14000432a;
    pbVar22 = FUN_140003190((longlong)pppppbVar25,pbVar26);
    plVar13 = DAT_1400132b8;
    *(byte **)(puVar40 + 0x38) = pbVar22;
    if (pbVar22[9] == 0) {
      if ((DAT_1400132b0 == 0) || (DAT_1400132b8 == (longlong *)0x0)) {
        cVar15 = '\0';
      }
      else {
        *pbVar22 = *pbVar22 ^ DAT_1400130c7;
        pbVar22[1] = pbVar22[1] ^ DAT_1400130c7;
        pbVar22[2] = pbVar22[2] ^ DAT_1400130c7;
        pbVar22[3] = pbVar22[3] ^ DAT_1400130c7;
        pbVar22[4] = pbVar22[4] ^ DAT_1400130c7;
        pbVar22[5] = pbVar22[5] ^ DAT_1400130c7;
        pbVar22[6] = pbVar22[6] ^ DAT_1400130c7;
        pbVar22[7] = pbVar22[7] ^ DAT_1400130c7;
        uVar2 = *(undefined8 *)(*plVar13 + (ulonglong)pbVar22[8] * 8);
        *(undefined8 *)(puVar40 + 0x20) = uVar2;
        puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
        puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
        puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
        puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
        puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
        puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
        puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
        puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
        uVar2 = *(undefined8 *)(pbVar22 + 0x12);
        uVar3 = *(undefined8 *)pbVar22;
        *(undefined8 *)(puVar40 + -8) = 0x1400043f1;
        cVar15 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
        DAT_140013201 = cVar15;
        pbVar22[9] = pbVar22[9] == 0;
        *pbVar22 = *pbVar22 ^ DAT_1400130c7;
        pbVar22[1] = pbVar22[1] ^ DAT_1400130c7;
        pbVar22[2] = pbVar22[2] ^ DAT_1400130c7;
        pbVar22[3] = pbVar22[3] ^ DAT_1400130c7;
        pbVar22[4] = pbVar22[4] ^ DAT_1400130c7;
        pbVar22[5] = pbVar22[5] ^ DAT_1400130c7;
        pbVar22[6] = pbVar22[6] ^ DAT_1400130c7;
        pbVar22[7] = pbVar22[7] ^ DAT_1400130c7;
      }
      if (cVar15 == '\0') goto LAB_14000527b;
    }
    plVar13 = DAT_1400132b8;
    if (pbVar26 != (byte *)0x0) {
      uVar43 = (ulonglong)DAT_14001321c;
      *(undefined8 **)(puVar40 + 0x48) = &DAT_1400132c0 + uVar43;
      *(ulonglong *)(puVar40 + 0x20) = uVar43 * 8 + 0x1400132c1;
      *(ulonglong *)(puVar40 + 0x50) = uVar43 * 8 + 0x1400132c2;
      *(ulonglong *)(puVar40 + 0x58) = uVar43 * 8 + 0x1400132c3;
      *(ulonglong *)(puVar40 + 0x60) = uVar43 * 8 + 0x1400132c4;
      *(ulonglong *)(puVar40 + 0x68) = uVar43 * 8 + 0x1400132c5;
      *(ulonglong *)(puVar40 + 0x70) = uVar43 * 8 + 0x1400132c6;
      *(ulonglong *)(puVar40 + 0x78) = uVar43 * 8 + 0x1400132c7;
      uVar43 = (ulonglong)DAT_14001321d;
      local_468 = (byte *)(&DAT_1400132c0 + uVar43);
      local_460 = (byte *)((longlong)&DAT_1400132c0 + uVar43 * 8 + 1);
      local_458 = (byte *)((longlong)&DAT_1400132c0 + uVar43 * 8 + 2);
      local_450 = (byte *)((longlong)&DAT_1400132c0 + uVar43 * 8 + 3);
      local_448 = (byte *)((longlong)&DAT_1400132c0 + uVar43 * 8 + 4);
      local_440 = (byte *)((longlong)&DAT_1400132c0 + uVar43 * 8 + 5);
      local_438 = (byte *)((longlong)&DAT_1400132c0 + uVar43 * 8 + 6);
      local_430 = (byte *)((longlong)&DAT_1400132c0 + uVar43 * 8 + 7);
      uVar39 = (ulonglong)DAT_14001321e;
      local_428 = (byte *)(&DAT_1400132c0 + uVar39);
      local_420 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
      local_418 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
      local_410 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
      local_408 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
      local_400 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
      local_3f8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
      local_3f0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
      uVar39 = (ulonglong)DAT_14001321f;
      local_3e8 = (byte *)(&DAT_1400132c0 + uVar39);
      local_3e0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
      local_3d8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
      local_3d0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
      local_3c8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
      local_3c0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
      local_3b8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
      local_3b0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
      lVar30 = (ulonglong)DAT_1400133c0 * 8;
      local_3a8 = (byte *)(&DAT_140013340 + DAT_1400133c0);
      local_3a0 = (byte *)((longlong)&DAT_140013340 + lVar30 + 1);
      pbVar48 = (byte *)((longlong)&DAT_140013340 + lVar30 + 3);
      lVar1 = (ulonglong)DAT_1400133c1 * 8;
      local_398 = (byte *)(&DAT_140013340 + DAT_1400133c1);
      local_390 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
      local_1e8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
      *(longlong *)(puVar40 + 0x30) = lVar1 + 0x140013344;
      local_388 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
      local_380 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
      local_378 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
      lVar27 = (ulonglong)DAT_1400133c2 * 8;
      local_370 = (byte *)(&DAT_140013340 + DAT_1400133c2);
      local_368 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
      local_360 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
      local_358 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
      local_350 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
      local_348 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
      local_340 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
      local_338 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
      lVar27 = (ulonglong)DAT_1400133c3 * 8;
      local_330 = (byte *)(&DAT_140013340 + DAT_1400133c3);
      local_328 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
      local_320 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
      local_318 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
      local_310 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
      local_308 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
      local_300 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
      local_2f8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
      lVar27 = (ulonglong)DAT_1400133c4 * 8;
      local_2f0 = (byte *)(&DAT_140013340 + DAT_1400133c4);
      local_2e8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
      local_2e0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
      local_2d8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
      local_2d0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
      local_2c8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
      local_2c0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
      local_2b8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
      uVar39 = (ulonglong)DAT_1400133c5;
      local_2b0 = (byte *)(&DAT_140013340 + uVar39);
      local_2a8 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 1);
      local_2a0 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 2);
      local_298 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 3);
      local_290 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 4);
      local_288 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 5);
      local_280 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 6);
      local_278 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 7);
      lVar27 = (ulonglong)DAT_1400133c6 * 8;
      local_270 = (byte *)(&DAT_140013340 + DAT_1400133c6);
      local_268 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
      local_260 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
      local_258 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
      local_250 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
      local_248 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
      local_240 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
      local_238 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
      lVar27 = (ulonglong)DAT_1400133c7 * 8;
      local_230 = (byte *)(&DAT_140013340 + DAT_1400133c7);
      local_228 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
      local_220 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
      local_218 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
      local_210 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
      local_208 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
      local_200 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
      local_1f8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
      pppppbVar36 = pppppbVar25;
      do {
        pbVar18[(longlong)pppppbVar25] =
             pbVar18[(longlong)pppppbVar25] ^ **(byte **)(puVar40 + 0x48);
        bVar33 = pbVar18[(longlong)pppppbVar25];
        bVar16 = **(byte **)(puVar40 + 0x20);
        pbVar18[(longlong)pppppbVar25] = bVar33 ^ bVar16;
        bVar16 = bVar33 ^ bVar16 ^ **(byte **)(puVar40 + 0x50);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x58);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x60);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x68);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x70);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x78);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *(byte *)(&DAT_1400132c0 + uVar43);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_460;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_458;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_450;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_448;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_440;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_438;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_430;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_428;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_420;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_418;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_410;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_408;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_400;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3f8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3f0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3e8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3e0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3d8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3d0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3c8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3c0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3b8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3b0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3a8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_3a0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 2);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *pbVar48;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 4);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 5);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 6);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 7);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_398;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_390;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar1 + 2);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_1e8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x30);
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_388;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_380;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_378;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_370;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_368;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_360;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_358;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_350;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_348;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_340;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_338;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_330;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_328;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_320;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_318;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_310;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_308;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_300;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2f8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2f0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2e8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2e0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2d8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2d0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2c8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2c0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2b8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2b0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2a8;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_2a0;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_298;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_290;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_288;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_280;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_278;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_270;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_268;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_260;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_258;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_250;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_248;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_240;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_238;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_230;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_228;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_220;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_218;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_210;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_208;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        bVar16 = bVar16 ^ *local_200;
        pbVar18[(longlong)pppppbVar25] = bVar16;
        pbVar18[(longlong)pppppbVar25] = bVar16 ^ *local_1f8;
        uVar39 = 0;
        do {
          uVar31 = (ulonglong)(byte)(&DAT_140013220)[uVar39];
          bVar33 = *(byte *)(&DAT_140013230 + uVar31);
          bVar16 = *(byte *)pppppbVar36;
          *(byte *)pppppbVar36 = bVar33 ^ bVar16;
          bVar16 = bVar33 ^ bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
          *(byte *)pppppbVar36 = bVar16;
          uVar31 = (ulonglong)(byte)(&DAT_140013221)[uVar39];
          bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
          *(byte *)pppppbVar36 = bVar16;
          uVar31 = (ulonglong)(byte)(&DAT_140013222)[uVar39];
          bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
          *(byte *)pppppbVar36 = bVar16;
          uVar31 = (ulonglong)(byte)(&DAT_140013223)[uVar39];
          bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
          *(byte *)pppppbVar36 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
          *(byte *)pppppbVar36 = bVar16;
          *(byte *)pppppbVar36 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
          uVar39 = uVar39 + 4;
        } while (uVar39 < 0xc);
        pbVar18 = pbVar18 + 1;
        pppppbVar36 = (byte *****)((longlong)pppppbVar36 + 1);
      } while (pbVar18 < local_1f0);
      pbVar22 = *(byte **)(puVar40 + 0x38);
      plVar21 = *(longlong **)(puVar40 + 0x28);
    }
    if (((pbVar22[9] != 0) && (DAT_1400132b0 != 0)) && (DAT_1400132b8 != (longlong *)0x0)) {
      *pbVar22 = *pbVar22 ^ DAT_1400130c7;
      pbVar22[1] = pbVar22[1] ^ DAT_1400130c7;
      pbVar22[2] = pbVar22[2] ^ DAT_1400130c7;
      pbVar22[3] = pbVar22[3] ^ DAT_1400130c7;
      pbVar22[4] = pbVar22[4] ^ DAT_1400130c7;
      pbVar22[5] = pbVar22[5] ^ DAT_1400130c7;
      pbVar22[6] = pbVar22[6] ^ DAT_1400130c7;
      pbVar22[7] = pbVar22[7] ^ DAT_1400130c7;
      uVar2 = *(undefined8 *)(*plVar13 + (ulonglong)pbVar22[8] * 8);
      *(undefined8 *)(puVar40 + 0x20) = uVar2;
      puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
      puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
      puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
      puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
      puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
      puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
      puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
      puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
      uVar2 = *(undefined8 *)(pbVar22 + 0x12);
      uVar3 = *(undefined8 *)pbVar22;
      *(undefined8 *)(puVar40 + -8) = 0x14000521c;
      DAT_140013201 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
      pbVar22[9] = pbVar22[9] == 0;
      *pbVar22 = *pbVar22 ^ DAT_1400130c7;
      pbVar22[1] = pbVar22[1] ^ DAT_1400130c7;
      pbVar22[2] = pbVar22[2] ^ DAT_1400130c7;
      pbVar22[3] = pbVar22[3] ^ DAT_1400130c7;
      pbVar22[4] = pbVar22[4] ^ DAT_1400130c7;
      pbVar22[5] = pbVar22[5] ^ DAT_1400130c7;
      pbVar22[6] = pbVar22[6] ^ DAT_1400130c7;
      pbVar22[7] = pbVar22[7] ^ DAT_1400130c7;
    }
  }
LAB_14000527b:
  uVar43 = 0;
  if (local_e0 < 0x10) {
LAB_1400052b8:
    local_e8 = (byte *)0x0;
    local_e0 = 0xf;
    local_f8 = 0;
    if (0xf < (ulonglong)plVar21[3]) {
      pvVar23 = (void *)*plVar21;
      if ((0xfff < plVar21[3] + 1U) &&
         (uVar39 = (longlong)pvVar23 + (-8 - (longlong)*(void **)((longlong)pvVar23 + -8)),
         pvVar23 = *(void **)((longlong)pvVar23 + -8), 0x1f < uVar39)) goto LAB_140005301;
      goto LAB_14000530b;
    }
  }
  else {
    pvVar20 = (void *)CONCAT71(uStack_f7,local_f8);
    pvVar23 = pvVar20;
    if ((local_e0 + 1 < 0x1000) ||
       (pvVar23 = *(void **)((longlong)pvVar20 + -8),
       (ulonglong)((longlong)pvVar20 + (-8 - (longlong)pvVar23)) < 0x20)) {
      *(undefined8 *)(puVar40 + -8) = 0x1400052b8;
      free(pvVar23);
      goto LAB_1400052b8;
    }
LAB_140005301:
    pcVar49 = (code *)swi(0x29);
    pvVar23 = (void *)(*pcVar49)(5);
    puVar40 = puVar40 + 8;
LAB_14000530b:
    *(undefined8 *)(puVar40 + -8) = 0x140005310;
    free(pvVar23);
  }
  ppppbVar4 = local_118;
  piVar41 = local_1d8;
  plVar21[2] = 0;
  plVar21[3] = 0xf;
  *(undefined1 *)plVar21 = 0;
  uVar39 = DAT_140013be0;
  local_1e0 = (basic_ostream<> *)cout_exref;
  if (local_100 == '\0') {
    pppppbVar25 = &local_128;
    if (0xf < local_110) {
      pppppbVar25 = (byte *****)local_128;
    }
    *(byte ******)(puVar40 + 0x38) = pppppbVar25;
    pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    uVar31 = uVar43;
    if (DAT_14001321a == '\0') {
      do {
        (&DAT_1400133d0)[uVar31] = ~DAT_1400130b8 ^ (ulonglong)pbVar48 ^ uVar39;
        DAT_1400130b8 = DAT_1400130b8 - 0xffffffff;
        uVar31 = uVar31 + 1;
      } while (uVar31 != 0x100);
      DAT_14001321a = '\x01';
      pppppbVar25 = *(byte ******)(puVar40 + 0x38);
    }
    *(ulonglong *)(puVar40 + 0x20) = uVar39;
    if ((byte *****)local_118 != (byte *****)0x0) {
      do {
        bVar16 = *(byte *)((longlong)pppppbVar25 + (longlong)(int)uVar43);
        puVar40[0x20] = bVar16 ^ (byte)uVar39;
        puVar40[0x21] = puVar40[0x21] ^ bVar16;
        puVar40[0x22] = puVar40[0x22] ^ bVar16;
        puVar40[0x23] = puVar40[0x23] ^ bVar16;
        puVar40[0x24] = puVar40[0x24] ^ bVar16;
        puVar40[0x25] = puVar40[0x25] ^ bVar16;
        puVar40[0x26] = puVar40[0x26] ^ bVar16;
        puVar40[0x27] = puVar40[0x27] ^ bVar16;
        uVar39 = *(ulonglong *)(puVar40 + 0x20) ^ (&DAT_1400133d0)[(byte)~bVar16];
        *(ulonglong *)(puVar40 + 0x20) = uVar39;
        uVar17 = (int)uVar43 + 1;
        uVar43 = (ulonglong)uVar17;
      } while ((byte *****)(longlong)(int)uVar17 < local_118);
    }
    if (*local_1d8 < DAT_140013c50) {
      *(undefined8 *)(puVar40 + -8) = 0x14000544a;
      FUN_14000e96c(&DAT_140013c50);
      if (DAT_140013c50 == -1) {
        *(undefined8 *)(puVar40 + -8) = 0x140005466;
        _DAT_140013c48 = uVar39;
        _Init_thread_footer(&DAT_140013c50);
      }
      pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    }
    if (*piVar41 < DAT_140013c40) {
      *(undefined8 *)(puVar40 + -8) = 0x140005483;
      FUN_14000e96c(&DAT_140013c40);
      if (DAT_140013c40 == -1) {
        _DAT_140013c38 = CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
        *(undefined8 *)(puVar40 + -8) = 0x1400054a6;
        _Init_thread_footer(&DAT_140013c40);
      }
      pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    }
    pcVar49 = DAT_140013210;
    bVar16 = *(byte *)pppppbVar25;
    bVar33 = DAT_140013bd0;
    if ((byte *****)0x1 < ppppbVar4) {
      bVar33 = ((byte *)((longlong)ppppbVar4 + -1))[(longlong)pppppbVar25];
    }
    *(byte *****)(puVar40 + 0x28) = ppppbVar4;
    *(byte *****)(puVar40 + 0x30) = ppppbVar4;
    uVar17 = 0;
    bVar29 = (byte)ppppbVar4;
    bVar28 = bVar29;
    do {
      bVar29 = bVar29 ^ bVar16;
      bVar28 = bVar28 ^ bVar33;
      uVar17 = uVar17 + 1;
    } while (uVar17 < 8);
    puVar40[0x28] = bVar29;
    puVar40[0x30] = bVar28;
    uVar43 = (longlong)ppppbVar4 * 8;
    bVar50 = DAT_140013200 == '\0';
    _DAT_140013c38 = (ulonglong)ppppbVar4 ^ (ulonglong)pbVar48 ^ _DAT_140013c38;
    puVar40[0x20] = puVar40[0x20] ^ (byte)_DAT_140013c38;
    lVar30 = *(longlong *)(puVar40 + 0x28);
    lVar1 = *(longlong *)(puVar40 + 0x30);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x38;
    uVar31 = (ulonglong)ppppbVar4 ^ _DAT_140013c38 ^ (ulonglong)pbVar48;
    puVar40[0x21] = (byte)(uVar31 >> 8) ^ (byte)(uVar39 >> 8);
    lVar27 = lVar30;
    if (!bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x38;
    bVar28 = (byte)uVar43;
    uVar31 = (longlong)ppppbVar4 << (bVar28 & 0xf) ^ uVar31 ^ (ulonglong)pbVar48;
    puVar40[0x22] = (byte)(uVar31 >> 0x10) ^ (byte)(uVar39 >> 0x10);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x30;
    uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x18) * -0x18 & 0x3f) ^ uVar31 ^
             (ulonglong)pbVar48;
    puVar40[0x23] = (byte)(uVar31 >> 0x18) ^ (byte)(uVar39 >> 0x18);
    lVar27 = lVar30;
    if (!bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x28;
    uVar31 = (longlong)ppppbVar4 << (bVar28 & 0x1f) ^ uVar31 ^ (ulonglong)pbVar48;
    puVar40[0x24] = (byte)(uVar31 >> 0x20) ^ (byte)(uVar39 >> 0x20);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x20;
    uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x28) * -0x28 & 0x3f) ^ uVar31 ^
             (ulonglong)pbVar48;
    puVar40[0x25] = (byte)(uVar31 >> 0x28) ^ (byte)((uVar39 ^ lVar27 << 0x20) >> 0x28);
    lVar27 = lVar30;
    if (!bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x18;
    uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x30) * -0x30 & 0x3f) ^ uVar31 ^
             (ulonglong)pbVar48;
    puVar40[0x26] = (byte)(uVar31 >> 0x30) ^ (byte)((uVar39 ^ lVar27 << 0x18) >> 0x30);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x10;
    auVar8._8_8_ = 0;
    auVar8._0_8_ = uVar43;
    lVar35 = SUB168(ZEXT816(0x2492492492492493) * auVar8,8);
    bVar28 = (byte)((ulonglong)
                    ((longlong)ppppbVar4 <<
                    (bVar28 + (char)((uVar43 - lVar35 >> 1) + lVar35 >> 5) * -0x38 & 0x3f)) >> 0x38)
             ^ (byte)(uVar31 >> 0x38) ^ (byte)((uVar39 ^ lVar27 << 0x10) >> 0x38) ^
             DAT_140013be8._7_1_;
    pppppbVar25 = (byte *****)(ulonglong)bVar28;
    puVar40[0x27] = bVar28;
    if (!bVar50) {
      lVar30 = lVar1;
    }
    uVar43 = DAT_140013bd8 + (ulonglong)bVar16 * -0x80 + (ulonglong)bVar33 * -0xff ^ lVar30 << 8 ^
             *(ulonglong *)(puVar40 + 0x20) ^ _DAT_140013c48;
    _DAT_140013c48 = 0;
    _DAT_140013c38 = 0;
    DAT_140013200 = '\0';
    if (uVar43 != local_108) {
      *(undefined8 *)(puVar40 + -8) = 0x1400057bd;
      plVar21 = FUN_140003640((longlong *)&local_1d0,local_108,uVar43);
      *(undefined8 *)(puVar40 + -8) = 0x1400057c9;
      (*pcVar49)(plVar21,&local_128);
    }
  }
  uVar39 = 0;
  *(undefined8 *)(puVar40 + -8) = 0x1400057dc;
  FUN_14000d740(&local_88,&local_128);
  ppppbVar4 = local_118;
  piVar41 = local_1d8;
  uVar43 = DAT_140013be0;
  if (local_100 == '\0') {
    pppppbVar25 = &local_128;
    if (0xf < local_110) {
      pppppbVar25 = (byte *****)local_128;
    }
    *(byte ******)(puVar40 + 0x38) = pppppbVar25;
    pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    uVar31 = uVar39;
    if (DAT_14001321a == '\0') {
      do {
        (&DAT_1400133d0)[uVar31] = ~DAT_1400130b8 ^ (ulonglong)pbVar48 ^ uVar43;
        DAT_1400130b8 = DAT_1400130b8 - 0xffffffff;
        uVar31 = uVar31 + 1;
      } while (uVar31 != 0x100);
      DAT_14001321a = '\x01';
      pppppbVar25 = *(byte ******)(puVar40 + 0x38);
    }
    *(ulonglong *)(puVar40 + 0x20) = uVar43;
    if ((byte *****)local_118 != (byte *****)0x0) {
      do {
        bVar16 = *(byte *)((longlong)pppppbVar25 + (longlong)(int)uVar39);
        puVar40[0x20] = (byte)uVar43 ^ bVar16;
        puVar40[0x21] = puVar40[0x21] ^ bVar16;
        puVar40[0x22] = puVar40[0x22] ^ bVar16;
        puVar40[0x23] = puVar40[0x23] ^ bVar16;
        puVar40[0x24] = puVar40[0x24] ^ bVar16;
        puVar40[0x25] = puVar40[0x25] ^ bVar16;
        puVar40[0x26] = puVar40[0x26] ^ bVar16;
        puVar40[0x27] = puVar40[0x27] ^ bVar16;
        uVar43 = *(ulonglong *)(puVar40 + 0x20) ^ (&DAT_1400133d0)[(byte)~bVar16];
        *(ulonglong *)(puVar40 + 0x20) = uVar43;
        uVar17 = (int)uVar39 + 1;
        uVar39 = (ulonglong)uVar17;
      } while ((byte *****)(longlong)(int)uVar17 < local_118);
    }
    if (*local_1d8 < DAT_140013c50) {
      *(undefined8 *)(puVar40 + -8) = 0x1400058ea;
      FUN_14000e96c(&DAT_140013c50);
      if (DAT_140013c50 == -1) {
        *(undefined8 *)(puVar40 + -8) = 0x140005906;
        _DAT_140013c48 = uVar43;
        _Init_thread_footer(&DAT_140013c50);
      }
      pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    }
    if (*piVar41 < DAT_140013c40) {
      *(undefined8 *)(puVar40 + -8) = 0x140005923;
      FUN_14000e96c(&DAT_140013c40);
      if (DAT_140013c40 == -1) {
        _DAT_140013c38 = CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
        *(undefined8 *)(puVar40 + -8) = 0x140005946;
        _Init_thread_footer(&DAT_140013c40);
      }
      pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    }
    pcVar49 = DAT_140013210;
    bVar16 = *(byte *)pppppbVar25;
    bVar33 = DAT_140013bd0;
    if ((byte *****)0x1 < ppppbVar4) {
      bVar33 = ((byte *)((longlong)pppppbVar25 + -1))[(longlong)ppppbVar4];
    }
    *(byte *****)(puVar40 + 0x28) = ppppbVar4;
    *(byte *****)(puVar40 + 0x30) = ppppbVar4;
    uVar17 = 0;
    bVar29 = (byte)ppppbVar4;
    bVar28 = bVar29;
    do {
      bVar29 = bVar29 ^ bVar16;
      bVar28 = bVar28 ^ bVar33;
      uVar17 = uVar17 + 1;
    } while (uVar17 < 8);
    puVar40[0x28] = bVar29;
    puVar40[0x30] = bVar28;
    uVar43 = (longlong)ppppbVar4 * 8;
    bVar50 = DAT_140013200 == '\0';
    _DAT_140013c38 = (ulonglong)ppppbVar4 ^ (ulonglong)pbVar48 ^ _DAT_140013c38;
    puVar40[0x20] = puVar40[0x20] ^ (byte)_DAT_140013c38;
    lVar30 = *(longlong *)(puVar40 + 0x28);
    lVar1 = *(longlong *)(puVar40 + 0x30);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x38;
    uVar31 = _DAT_140013c38 ^ (ulonglong)ppppbVar4 ^ (ulonglong)pbVar48;
    puVar40[0x21] = (byte)(uVar39 >> 8) ^ (byte)(uVar31 >> 8);
    lVar27 = lVar30;
    if (!bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x38;
    bVar28 = (byte)uVar43;
    uVar31 = (longlong)ppppbVar4 << (bVar28 & 0xf) ^ uVar31 ^ (ulonglong)pbVar48;
    puVar40[0x22] = (byte)(uVar39 >> 0x10) ^ (byte)(uVar31 >> 0x10);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x30;
    uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x18) * -0x18 & 0x3f) ^ uVar31 ^
             (ulonglong)pbVar48;
    puVar40[0x23] = (byte)(uVar39 >> 0x18) ^ (byte)(uVar31 >> 0x18);
    lVar27 = lVar30;
    if (!bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x28;
    uVar31 = (longlong)ppppbVar4 << (bVar28 & 0x1f) ^ uVar31 ^ (ulonglong)pbVar48;
    puVar40[0x24] = (byte)(uVar39 >> 0x20) ^ (byte)(uVar31 >> 0x20);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x20;
    uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x28) * -0x28 & 0x3f) ^ uVar31 ^
             (ulonglong)pbVar48;
    puVar40[0x25] = (byte)((uVar39 ^ lVar27 << 0x20) >> 0x28) ^ (byte)(uVar31 >> 0x28);
    lVar27 = lVar30;
    if (!bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x18;
    uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x30) * -0x30 & 0x3f) ^ uVar31 ^
             (ulonglong)pbVar48;
    puVar40[0x26] = (byte)((uVar39 ^ lVar27 << 0x18) >> 0x30) ^ (byte)(uVar31 >> 0x30);
    lVar27 = lVar30;
    if (bVar50) {
      lVar27 = lVar1;
    }
    uVar39 = *(ulonglong *)(puVar40 + 0x20);
    *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x10;
    auVar9._8_8_ = 0;
    auVar9._0_8_ = uVar43;
    lVar35 = SUB168(ZEXT816(0x2492492492492493) * auVar9,8);
    bVar28 = (byte)((ulonglong)
                    ((longlong)ppppbVar4 <<
                    (bVar28 + (char)((uVar43 - lVar35 >> 1) + lVar35 >> 5) * -0x38 & 0x3f)) >> 0x38)
             ^ (byte)((uVar39 ^ lVar27 << 0x10) >> 0x38) ^ (byte)(uVar31 >> 0x38) ^
             DAT_140013be8._7_1_;
    pppppbVar25 = (byte *****)(ulonglong)bVar28;
    puVar40[0x27] = bVar28;
    if (!bVar50) {
      lVar30 = lVar1;
    }
    uVar43 = DAT_140013bd8 + (ulonglong)bVar16 * -0x80 + (ulonglong)bVar33 * -0xff ^ lVar30 << 8 ^
             *(ulonglong *)(puVar40 + 0x20) ^ _DAT_140013c48;
    _DAT_140013c48 = 0;
    _DAT_140013c38 = 0;
    DAT_140013200 = '\0';
    if (uVar43 != local_108) {
      *(undefined8 *)(puVar40 + -8) = 0x140005c5e;
      plVar21 = FUN_140003640((longlong *)&local_198,local_108,uVar43);
      *(undefined8 *)(puVar40 + -8) = 0x140005c6a;
      (*pcVar49)(plVar21,&local_128);
    }
  }
  uVar43 = 0;
  *(undefined8 *)(puVar40 + -8) = 0x140005c7d;
  FUN_14000d740((undefined8 *)&local_f8,&local_128);
  pbVar26 = local_e8;
  *(byte **)(puVar40 + 0x50) = local_e8;
  local_100 = 1;
  pppppbVar36 = &local_128;
  if (0xf < local_110) {
    pppppbVar36 = (byte *****)local_128;
  }
  if (DAT_140013219 == '\0') {
    *(undefined8 *)(puVar40 + -8) = 0x140005cb6;
    FUN_140001c90();
  }
  if ((pppppbVar36 != (byte *****)0x0) && (pbVar26 != (byte *)0x0)) {
    *(undefined8 *)(puVar40 + -8) = 0x140005cd3;
    pbVar18 = FUN_140003190((longlong)pppppbVar36,pbVar26);
    plVar21 = DAT_1400132b8;
    *(byte **)(puVar40 + 0x48) = pbVar18;
    if (pbVar18[9] == 0) {
      if ((DAT_1400132b0 == 0) || (DAT_1400132b8 == (longlong *)0x0)) {
        cVar15 = '\0';
      }
      else {
        *pbVar18 = *pbVar18 ^ DAT_1400130c7;
        pbVar18[1] = pbVar18[1] ^ DAT_1400130c7;
        pbVar18[2] = pbVar18[2] ^ DAT_1400130c7;
        pbVar18[3] = pbVar18[3] ^ DAT_1400130c7;
        pbVar18[4] = pbVar18[4] ^ DAT_1400130c7;
        pbVar18[5] = pbVar18[5] ^ DAT_1400130c7;
        pbVar18[6] = pbVar18[6] ^ DAT_1400130c7;
        pbVar18[7] = pbVar18[7] ^ DAT_1400130c7;
        uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar18[8] * 8);
        *(undefined8 *)(puVar40 + 0x20) = uVar2;
        puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
        puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
        puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
        puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
        puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
        puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
        puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
        puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
        uVar2 = *(undefined8 *)(pbVar18 + 0x12);
        uVar3 = *(undefined8 *)pbVar18;
        *(undefined8 *)(puVar40 + -8) = 0x140005d9a;
        cVar15 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
        DAT_140013201 = cVar15;
        pbVar18[9] = pbVar18[9] == 0;
        *pbVar18 = *pbVar18 ^ DAT_1400130c7;
        pbVar18[1] = pbVar18[1] ^ DAT_1400130c7;
        pbVar18[2] = pbVar18[2] ^ DAT_1400130c7;
        pbVar18[3] = pbVar18[3] ^ DAT_1400130c7;
        pbVar18[4] = pbVar18[4] ^ DAT_1400130c7;
        pbVar18[5] = pbVar18[5] ^ DAT_1400130c7;
        pbVar18[6] = pbVar18[6] ^ DAT_1400130c7;
        pbVar18[7] = pbVar18[7] ^ DAT_1400130c7;
      }
      if (cVar15 == '\0') goto LAB_140006c27;
    }
    plVar21 = DAT_1400132b8;
    if (pbVar26 != (byte *)0x0) {
      uVar39 = (ulonglong)DAT_14001321c;
      *(undefined8 **)(puVar40 + 0x38) = &DAT_1400132c0 + uVar39;
      local_1e8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
      local_1f0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
      local_1f8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
      local_200 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
      local_208 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
      local_210 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
      local_218 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
      uVar39 = (ulonglong)DAT_14001321d;
      local_220 = (byte *)(&DAT_1400132c0 + uVar39);
      local_228 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
      local_230 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
      local_238 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
      local_240 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
      local_248 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
      local_250 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
      local_258 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
      uVar39 = (ulonglong)DAT_14001321e;
      local_260 = (byte *)(&DAT_1400132c0 + uVar39);
      local_268 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
      local_270 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
      local_278 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
      local_280 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
      local_288 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
      local_290 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
      local_298 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
      uVar39 = (ulonglong)DAT_14001321f;
      local_2a0 = (byte *)(&DAT_1400132c0 + uVar39);
      local_2a8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
      local_2b0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
      local_2b8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
      local_2c0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
      local_2c8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
      local_2d0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
      local_2d8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
      lVar30 = (ulonglong)DAT_1400133c0 * 8;
      local_2e0 = (byte *)(&DAT_140013340 + DAT_1400133c0);
      local_2e8 = (byte *)((longlong)&DAT_140013340 + lVar30 + 1);
      pppppbVar25 = (byte *****)((longlong)&DAT_140013340 + lVar30 + 3);
      pbVar48 = (byte *)((longlong)&DAT_140013340 + lVar30 + 4);
      lVar1 = (ulonglong)DAT_1400133c1 * 8;
      local_2f0 = (byte *)(&DAT_140013340 + DAT_1400133c1);
      local_2f8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
      pbVar26 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
      *(byte **)(puVar40 + 0x30) = pbVar26;
      *(longlong *)(puVar40 + 0x28) = lVar1 + 0x140013344;
      local_300 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
      local_308 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
      local_310 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
      lVar27 = (ulonglong)DAT_1400133c2 * 8;
      local_318 = (byte *)(&DAT_140013340 + DAT_1400133c2);
      local_320 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
      local_328 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
      local_330 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
      local_338 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
      local_340 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
      local_348 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
      local_350 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
      lVar27 = (ulonglong)DAT_1400133c3 * 8;
      local_358 = (byte *)(&DAT_140013340 + DAT_1400133c3);
      local_360 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
      local_368 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
      local_370 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
      local_378 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
      local_380 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
      local_388 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
      local_390 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
      lVar27 = (ulonglong)DAT_1400133c4 * 8;
      local_398 = (byte *)(&DAT_140013340 + DAT_1400133c4);
      local_3a0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
      local_3a8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
      local_3b0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
      local_3b8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
      local_3c0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
      local_3c8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
      local_3d0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
      lVar27 = (ulonglong)DAT_1400133c5 * 8;
      local_3d8 = (byte *)(&DAT_140013340 + DAT_1400133c5);
      local_3e0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
      local_3e8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
      local_3f0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
      local_3f8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
      local_400 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
      local_408 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
      local_410 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
      lVar27 = (ulonglong)DAT_1400133c6 * 8;
      local_418 = (byte *)(&DAT_140013340 + DAT_1400133c6);
      local_420 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
      local_428 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
      local_430 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
      local_438 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
      local_440 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
      local_448 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
      local_450 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
      uVar39 = (ulonglong)DAT_1400133c7;
      local_458 = (byte *)(&DAT_140013340 + uVar39);
      local_460 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 1);
      local_468 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 2);
      *(ulonglong *)(puVar40 + 0x78) = uVar39 * 8 + 0x140013343;
      *(ulonglong *)(puVar40 + 0x70) = uVar39 * 8 + 0x140013344;
      *(ulonglong *)(puVar40 + 0x68) = uVar39 * 8 + 0x140013345;
      *(ulonglong *)(puVar40 + 0x60) = uVar39 * 8 + 0x140013346;
      *(ulonglong *)(puVar40 + 0x58) = uVar39 * 8 + 0x140013347;
      pppppbVar37 = pppppbVar36;
      do {
        *(byte *)((longlong)pppppbVar36 + uVar43) =
             *(byte *)((longlong)pppppbVar36 + uVar43) ^ **(byte **)(puVar40 + 0x38);
        bVar16 = *(byte *)((longlong)pppppbVar36 + uVar43) ^ *local_1e8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_1f0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_1f8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_200;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_208;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_210;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_218;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_220;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_228;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_230;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_238;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_240;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_248;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_250;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_258;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_260;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_268;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_270;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_278;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_280;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_288;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_290;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_298;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2a0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2a8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2b0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2b8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2c0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2c8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2d0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2d8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2e0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2e8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 2);
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *(byte *)pppppbVar25;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *pbVar48;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 5);
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 6);
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 7);
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2f0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_2f8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar1 + 2);
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *pbVar26;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x28);
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_300;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_308;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_310;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_318;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_320;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_328;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_330;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_338;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_340;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_348;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_350;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_358;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_360;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_368;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_370;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_378;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_380;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_388;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_390;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_398;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3a0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3a8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3b0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3b8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3c0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3c8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3d0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3d8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3e0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3e8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3f0;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_3f8;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_400;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_408;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_410;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_418;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_420;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_428;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_430;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_438;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_440;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_448;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_450;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *(byte *)(&DAT_140013340 + uVar39);
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_460;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ *local_468;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x78);
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x70);
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x68);
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x60);
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
        *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16 ^ **(byte **)(puVar40 + 0x58);
        uVar31 = 0;
        do {
          uVar46 = (ulonglong)(byte)(&DAT_140013220)[uVar31];
          bVar33 = *(byte *)(&DAT_140013230 + uVar46);
          bVar16 = *(byte *)pppppbVar37;
          *(byte *)pppppbVar37 = bVar33 ^ bVar16;
          bVar16 = bVar33 ^ bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 1);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 2);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 3);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 4);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 5);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 6);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 7);
          *(byte *)pppppbVar37 = bVar16;
          uVar46 = (ulonglong)(byte)(&DAT_140013221)[uVar31];
          bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar46);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 1);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 2);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 3);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 4);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 5);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 6);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 7);
          *(byte *)pppppbVar37 = bVar16;
          uVar46 = (ulonglong)(byte)(&DAT_140013222)[uVar31];
          bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar46);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 1);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 2);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 3);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 4);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 5);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 6);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 7);
          *(byte *)pppppbVar37 = bVar16;
          uVar46 = (ulonglong)(byte)(&DAT_140013223)[uVar31];
          bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar46);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 1);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 2);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 3);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 4);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 5);
          *(byte *)pppppbVar37 = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 6);
          *(byte *)pppppbVar37 = bVar16;
          *(byte *)pppppbVar37 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 7);
          uVar31 = uVar31 + 4;
        } while (uVar31 < 0xc);
        uVar43 = uVar43 + 1;
        pppppbVar37 = (byte *****)((longlong)pppppbVar37 + 1);
        pbVar26 = *(byte **)(puVar40 + 0x30);
      } while (uVar43 < *(ulonglong *)(puVar40 + 0x50));
      pbVar18 = *(byte **)(puVar40 + 0x48);
    }
    if (((pbVar18[9] != 0) && (DAT_1400132b0 != 0)) && (DAT_1400132b8 != (longlong *)0x0)) {
      *pbVar18 = *pbVar18 ^ DAT_1400130c7;
      pbVar18[1] = pbVar18[1] ^ DAT_1400130c7;
      pbVar18[2] = pbVar18[2] ^ DAT_1400130c7;
      pbVar18[3] = pbVar18[3] ^ DAT_1400130c7;
      pbVar18[4] = pbVar18[4] ^ DAT_1400130c7;
      pbVar18[5] = pbVar18[5] ^ DAT_1400130c7;
      pbVar18[6] = pbVar18[6] ^ DAT_1400130c7;
      pbVar18[7] = pbVar18[7] ^ DAT_1400130c7;
      uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar18[8] * 8);
      *(undefined8 *)(puVar40 + 0x20) = uVar2;
      puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
      puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
      puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
      puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
      puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
      puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
      puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
      puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
      uVar2 = *(undefined8 *)(pbVar18 + 0x12);
      uVar3 = *(undefined8 *)pbVar18;
      *(undefined8 *)(puVar40 + -8) = 0x140006bc8;
      DAT_140013201 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
      pbVar18[9] = pbVar18[9] == 0;
      *pbVar18 = *pbVar18 ^ DAT_1400130c7;
      pbVar18[1] = pbVar18[1] ^ DAT_1400130c7;
      pbVar18[2] = pbVar18[2] ^ DAT_1400130c7;
      pbVar18[3] = pbVar18[3] ^ DAT_1400130c7;
      pbVar18[4] = pbVar18[4] ^ DAT_1400130c7;
      pbVar18[5] = pbVar18[5] ^ DAT_1400130c7;
      pbVar18[6] = pbVar18[6] ^ DAT_1400130c7;
      pbVar18[7] = pbVar18[7] ^ DAT_1400130c7;
    }
  }
LAB_140006c27:
  uVar43 = 0;
  if (local_e0 < 0x10) {
LAB_140006c68:
    local_e8 = (byte *)0x0;
    local_e0 = 0xf;
    local_f8 = 0;
    local_100 = '\x01';
    *(undefined8 *)(puVar40 + -8) = 0x140006c9b;
    FUN_14000d5f0((longlong *)&local_88,(longlong *)&local_128);
    ppppbVar4 = local_118;
    piVar41 = local_1d8;
    uVar39 = DAT_140013be0;
    if (local_100 == '\0') {
      pppppbVar25 = &local_128;
      if (0xf < local_110) {
        pppppbVar25 = (byte *****)local_128;
      }
      *(byte ******)(puVar40 + 0x38) = pppppbVar25;
      pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
      uVar31 = uVar43;
      if (DAT_14001321a == '\0') {
        do {
          (&DAT_1400133d0)[uVar31] = ~DAT_1400130b8 ^ (ulonglong)pbVar48 ^ uVar39;
          DAT_1400130b8 = DAT_1400130b8 - 0xffffffff;
          uVar31 = uVar31 + 1;
        } while (uVar31 != 0x100);
        DAT_14001321a = '\x01';
        pppppbVar25 = *(byte ******)(puVar40 + 0x38);
      }
      *(ulonglong *)(puVar40 + 0x20) = uVar39;
      if ((byte *****)local_118 != (byte *****)0x0) {
        do {
          bVar16 = *(byte *)((longlong)pppppbVar25 + (longlong)(int)uVar43);
          puVar40[0x20] = (byte)uVar39 ^ bVar16;
          puVar40[0x21] = puVar40[0x21] ^ bVar16;
          puVar40[0x22] = puVar40[0x22] ^ bVar16;
          puVar40[0x23] = puVar40[0x23] ^ bVar16;
          puVar40[0x24] = puVar40[0x24] ^ bVar16;
          puVar40[0x25] = puVar40[0x25] ^ bVar16;
          puVar40[0x26] = puVar40[0x26] ^ bVar16;
          puVar40[0x27] = puVar40[0x27] ^ bVar16;
          uVar39 = *(ulonglong *)(puVar40 + 0x20) ^ (&DAT_1400133d0)[(byte)~bVar16];
          *(ulonglong *)(puVar40 + 0x20) = uVar39;
          uVar17 = (int)uVar43 + 1;
          uVar43 = (ulonglong)uVar17;
        } while ((byte *****)(longlong)(int)uVar17 < local_118);
      }
      if (*local_1d8 < DAT_140013c50) {
        *(undefined8 *)(puVar40 + -8) = 0x140006daa;
        FUN_14000e96c(&DAT_140013c50);
        if (DAT_140013c50 == -1) {
          *(undefined8 *)(puVar40 + -8) = 0x140006dc6;
          _DAT_140013c48 = uVar39;
          _Init_thread_footer(&DAT_140013c50);
        }
        pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
      }
      if (*piVar41 < DAT_140013c40) {
        *(undefined8 *)(puVar40 + -8) = 0x140006de3;
        FUN_14000e96c(&DAT_140013c40);
        if (DAT_140013c40 == -1) {
          _DAT_140013c38 = CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
          *(undefined8 *)(puVar40 + -8) = 0x140006e06;
          _Init_thread_footer(&DAT_140013c40);
        }
        pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
      }
      pcVar49 = DAT_140013210;
      bVar16 = *(byte *)pppppbVar25;
      bVar33 = DAT_140013bd0;
      if ((byte *****)0x1 < ppppbVar4) {
        bVar33 = ((byte *)((longlong)ppppbVar4 + -1))[(longlong)pppppbVar25];
      }
      *(byte *****)(puVar40 + 0x28) = ppppbVar4;
      *(byte *****)(puVar40 + 0x30) = ppppbVar4;
      uVar17 = 0;
      bVar29 = (byte)ppppbVar4;
      bVar28 = bVar29;
      do {
        bVar29 = bVar29 ^ bVar16;
        bVar28 = bVar28 ^ bVar33;
        uVar17 = uVar17 + 1;
      } while (uVar17 < 8);
      puVar40[0x28] = bVar29;
      puVar40[0x30] = bVar28;
      uVar43 = (longlong)ppppbVar4 * 8;
      bVar50 = DAT_140013200 == '\0';
      _DAT_140013c38 = (ulonglong)ppppbVar4 ^ (ulonglong)pbVar48 ^ _DAT_140013c38;
      puVar40[0x20] = puVar40[0x20] ^ (byte)_DAT_140013c38;
      lVar30 = *(longlong *)(puVar40 + 0x28);
      lVar1 = *(longlong *)(puVar40 + 0x30);
      lVar27 = lVar30;
      if (bVar50) {
        lVar27 = lVar1;
      }
      uVar39 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x38;
      uVar31 = _DAT_140013c38 ^ (ulonglong)ppppbVar4 ^ (ulonglong)pbVar48;
      puVar40[0x21] = (byte)(uVar39 >> 8) ^ (byte)(uVar31 >> 8);
      lVar27 = lVar30;
      if (!bVar50) {
        lVar27 = lVar1;
      }
      uVar39 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x38;
      bVar28 = (byte)uVar43;
      uVar31 = (longlong)ppppbVar4 << (bVar28 & 0xf) ^ uVar31 ^ (ulonglong)pbVar48;
      puVar40[0x22] = (byte)(uVar39 >> 0x10) ^ (byte)(uVar31 >> 0x10);
      lVar27 = lVar30;
      if (bVar50) {
        lVar27 = lVar1;
      }
      uVar39 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x30;
      uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x18) * -0x18 & 0x3f) ^ uVar31 ^
               (ulonglong)pbVar48;
      puVar40[0x23] = (byte)(uVar39 >> 0x18) ^ (byte)(uVar31 >> 0x18);
      lVar27 = lVar30;
      if (!bVar50) {
        lVar27 = lVar1;
      }
      uVar39 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x28;
      uVar31 = (longlong)ppppbVar4 << (bVar28 & 0x1f) ^ uVar31 ^ (ulonglong)pbVar48;
      puVar40[0x24] = (byte)(uVar39 >> 0x20) ^ (byte)(uVar31 >> 0x20);
      lVar27 = lVar30;
      if (bVar50) {
        lVar27 = lVar1;
      }
      uVar39 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x20;
      uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x28) * -0x28 & 0x3f) ^ uVar31 ^
               (ulonglong)pbVar48;
      puVar40[0x25] = (byte)((uVar39 ^ lVar27 << 0x20) >> 0x28) ^ (byte)(uVar31 >> 0x28);
      lVar27 = lVar30;
      if (!bVar50) {
        lVar27 = lVar1;
      }
      uVar39 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x18;
      uVar31 = (longlong)ppppbVar4 << (bVar28 + (char)(uVar43 / 0x30) * -0x30 & 0x3f) ^ uVar31 ^
               (ulonglong)pbVar48;
      puVar40[0x26] = (byte)((uVar39 ^ lVar27 << 0x18) >> 0x30) ^ (byte)(uVar31 >> 0x30);
      lVar27 = lVar30;
      if (bVar50) {
        lVar27 = lVar1;
      }
      uVar39 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x10;
      auVar10._8_8_ = 0;
      auVar10._0_8_ = uVar43;
      lVar35 = SUB168(ZEXT816(0x2492492492492493) * auVar10,8);
      bVar28 = (byte)((ulonglong)
                      ((longlong)ppppbVar4 <<
                      (bVar28 + (char)((uVar43 - lVar35 >> 1) + lVar35 >> 5) * -0x38 & 0x3f)) >>
                     0x38) ^ (byte)((uVar39 ^ lVar27 << 0x10) >> 0x38) ^ (byte)(uVar31 >> 0x38) ^
               DAT_140013be8._7_1_;
      pppppbVar25 = (byte *****)(ulonglong)bVar28;
      puVar40[0x27] = bVar28;
      if (!bVar50) {
        lVar30 = lVar1;
      }
      uVar43 = DAT_140013bd8 + (ulonglong)bVar16 * -0x80 + (ulonglong)bVar33 * -0xff ^ lVar30 << 8 ^
               *(ulonglong *)(puVar40 + 0x20) ^ _DAT_140013c48;
      _DAT_140013c48 = 0;
      _DAT_140013c38 = 0;
      DAT_140013200 = '\0';
      if (uVar43 != local_108) {
        *(undefined8 *)(puVar40 + -8) = 0x14000711e;
        plVar21 = FUN_140003640((longlong *)&local_198,local_108,uVar43);
        *(undefined8 *)(puVar40 + -8) = 0x14000712a;
        (*pcVar49)(plVar21,&local_128);
      }
    }
    uVar43 = 0;
    *(undefined8 *)(puVar40 + -8) = 0x14000713d;
    FUN_14000d740((undefined8 *)&local_f8,&local_128);
    pbVar26 = local_e8;
    *(byte **)(puVar40 + 0x50) = local_e8;
    local_100 = 1;
    pppppbVar36 = &local_128;
    if (0xf < local_110) {
      pppppbVar36 = (byte *****)local_128;
    }
    if (DAT_140013219 == '\0') {
      *(undefined8 *)(puVar40 + -8) = 0x140007176;
      FUN_140001c90();
    }
    if ((pppppbVar36 != (byte *****)0x0) && (pbVar26 != (byte *)0x0)) {
      *(undefined8 *)(puVar40 + -8) = 0x140007193;
      pbVar18 = FUN_140003190((longlong)pppppbVar36,pbVar26);
      plVar21 = DAT_1400132b8;
      *(byte **)(puVar40 + 0x48) = pbVar18;
      if (pbVar18[9] == 0) {
        if ((DAT_1400132b0 == 0) || (DAT_1400132b8 == (longlong *)0x0)) {
          cVar15 = '\0';
        }
        else {
          *pbVar18 = *pbVar18 ^ DAT_1400130c7;
          pbVar18[1] = pbVar18[1] ^ DAT_1400130c7;
          pbVar18[2] = pbVar18[2] ^ DAT_1400130c7;
          pbVar18[3] = pbVar18[3] ^ DAT_1400130c7;
          pbVar18[4] = pbVar18[4] ^ DAT_1400130c7;
          pbVar18[5] = pbVar18[5] ^ DAT_1400130c7;
          pbVar18[6] = pbVar18[6] ^ DAT_1400130c7;
          pbVar18[7] = pbVar18[7] ^ DAT_1400130c7;
          uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar18[8] * 8);
          *(undefined8 *)(puVar40 + 0x20) = uVar2;
          puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
          puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
          puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
          puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
          puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
          puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
          puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
          puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
          uVar2 = *(undefined8 *)(pbVar18 + 0x12);
          uVar3 = *(undefined8 *)pbVar18;
          *(undefined8 *)(puVar40 + -8) = 0x14000725a;
          cVar15 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
          DAT_140013201 = cVar15;
          pbVar18[9] = pbVar18[9] == 0;
          *pbVar18 = *pbVar18 ^ DAT_1400130c7;
          pbVar18[1] = pbVar18[1] ^ DAT_1400130c7;
          pbVar18[2] = pbVar18[2] ^ DAT_1400130c7;
          pbVar18[3] = pbVar18[3] ^ DAT_1400130c7;
          pbVar18[4] = pbVar18[4] ^ DAT_1400130c7;
          pbVar18[5] = pbVar18[5] ^ DAT_1400130c7;
          pbVar18[6] = pbVar18[6] ^ DAT_1400130c7;
          pbVar18[7] = pbVar18[7] ^ DAT_1400130c7;
        }
        if (cVar15 == '\0') goto LAB_1400080b7;
      }
      plVar21 = DAT_1400132b8;
      if (pbVar26 != (byte *)0x0) {
        uVar39 = (ulonglong)DAT_14001321c;
        *(undefined8 **)(puVar40 + 0x38) = &DAT_1400132c0 + uVar39;
        local_1e8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
        local_1f0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
        local_1f8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
        local_200 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
        local_208 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
        local_210 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
        local_218 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
        uVar39 = (ulonglong)DAT_14001321d;
        local_220 = (byte *)(&DAT_1400132c0 + uVar39);
        local_228 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
        local_230 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
        local_238 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
        local_240 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
        local_248 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
        local_250 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
        local_258 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
        uVar39 = (ulonglong)DAT_14001321e;
        local_260 = (byte *)(&DAT_1400132c0 + uVar39);
        local_268 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
        local_270 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
        local_278 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
        local_280 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
        local_288 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
        local_290 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
        local_298 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
        uVar39 = (ulonglong)DAT_14001321f;
        local_2a0 = (byte *)(&DAT_1400132c0 + uVar39);
        local_2a8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
        local_2b0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
        local_2b8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
        local_2c0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
        local_2c8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
        local_2d0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
        local_2d8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
        lVar30 = (ulonglong)DAT_1400133c0 * 8;
        local_2e0 = (byte *)(&DAT_140013340 + DAT_1400133c0);
        local_2e8 = (byte *)((longlong)&DAT_140013340 + lVar30 + 1);
        pppppbVar25 = (byte *****)((longlong)&DAT_140013340 + lVar30 + 3);
        pbVar48 = (byte *)((longlong)&DAT_140013340 + lVar30 + 4);
        lVar1 = (ulonglong)DAT_1400133c1 * 8;
        local_2f0 = (byte *)(&DAT_140013340 + DAT_1400133c1);
        local_2f8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
        pbVar26 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
        *(byte **)(puVar40 + 0x30) = pbVar26;
        *(longlong *)(puVar40 + 0x28) = lVar1 + 0x140013344;
        local_300 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
        local_308 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
        local_310 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
        lVar27 = (ulonglong)DAT_1400133c2 * 8;
        local_318 = (byte *)(&DAT_140013340 + DAT_1400133c2);
        local_320 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
        local_328 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
        local_330 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
        local_338 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
        local_340 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
        local_348 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
        local_350 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
        lVar27 = (ulonglong)DAT_1400133c3 * 8;
        local_358 = (byte *)(&DAT_140013340 + DAT_1400133c3);
        local_360 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
        local_368 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
        local_370 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
        local_378 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
        local_380 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
        local_388 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
        local_390 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
        lVar27 = (ulonglong)DAT_1400133c4 * 8;
        local_398 = (byte *)(&DAT_140013340 + DAT_1400133c4);
        local_3a0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
        local_3a8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
        local_3b0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
        local_3b8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
        local_3c0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
        local_3c8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
        local_3d0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
        lVar27 = (ulonglong)DAT_1400133c5 * 8;
        local_3d8 = (byte *)(&DAT_140013340 + DAT_1400133c5);
        local_3e0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
        local_3e8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
        local_3f0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
        local_3f8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
        local_400 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
        local_408 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
        local_410 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
        lVar27 = (ulonglong)DAT_1400133c6 * 8;
        local_418 = (byte *)(&DAT_140013340 + DAT_1400133c6);
        local_420 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
        local_428 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
        local_430 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
        local_438 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
        local_440 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
        local_448 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
        local_450 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
        lVar27 = (ulonglong)DAT_1400133c7 * 8;
        local_458 = (byte *)(&DAT_140013340 + DAT_1400133c7);
        local_460 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
        local_468 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
        *(longlong *)(puVar40 + 0x78) = lVar27 + 0x140013343;
        *(longlong *)(puVar40 + 0x70) = lVar27 + 0x140013344;
        *(longlong *)(puVar40 + 0x68) = lVar27 + 0x140013345;
        *(longlong *)(puVar40 + 0x60) = lVar27 + 0x140013346;
        *(longlong *)(puVar40 + 0x58) = lVar27 + 0x140013347;
        pppppbVar37 = pppppbVar36;
        do {
          *(byte *)((longlong)pppppbVar36 + uVar43) =
               *(byte *)((longlong)pppppbVar36 + uVar43) ^ **(byte **)(puVar40 + 0x38);
          bVar16 = *(byte *)((longlong)pppppbVar36 + uVar43) ^ *local_1e8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_1f0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_1f8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_200;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_208;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_210;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_218;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_220;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_228;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_230;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_238;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_240;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_248;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_250;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_258;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_260;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_268;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_270;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_278;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_280;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_288;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_290;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_298;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2a0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2a8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2b0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2b8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2c0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2c8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2d0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2d8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2e0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2e8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 2);
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *(byte *)pppppbVar25;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *pbVar48;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 5);
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 6);
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 7);
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2f0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_2f8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar1 + 2);
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *pbVar26;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x28);
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_300;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_308;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_310;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_318;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_320;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_328;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_330;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_338;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_340;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_348;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_350;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_358;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_360;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_368;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_370;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_378;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_380;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_388;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_390;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_398;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3a0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3a8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3b0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3b8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3c0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3c8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3d0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3d8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3e0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3e8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3f0;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_3f8;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_400;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_408;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_410;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_418;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_420;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_428;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_430;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_438;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_440;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_448;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_450;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *(byte *)(&DAT_140013340 + DAT_1400133c7);
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_460;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ *local_468;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x78);
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x70);
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x68);
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x60);
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
          *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16 ^ **(byte **)(puVar40 + 0x58);
          uVar39 = 0;
          do {
            uVar31 = (ulonglong)(byte)(&DAT_140013220)[uVar39];
            bVar33 = *(byte *)(&DAT_140013230 + uVar31);
            bVar16 = *(byte *)pppppbVar37;
            *(byte *)pppppbVar37 = bVar33 ^ bVar16;
            bVar16 = bVar33 ^ bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
            *(byte *)pppppbVar37 = bVar16;
            uVar31 = (ulonglong)(byte)(&DAT_140013221)[uVar39];
            bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
            *(byte *)pppppbVar37 = bVar16;
            uVar31 = (ulonglong)(byte)(&DAT_140013222)[uVar39];
            bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
            *(byte *)pppppbVar37 = bVar16;
            uVar31 = (ulonglong)(byte)(&DAT_140013223)[uVar39];
            bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
            *(byte *)pppppbVar37 = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
            *(byte *)pppppbVar37 = bVar16;
            *(byte *)pppppbVar37 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
            uVar39 = uVar39 + 4;
          } while (uVar39 < 0xc);
          uVar43 = uVar43 + 1;
          pppppbVar37 = (byte *****)((longlong)pppppbVar37 + 1);
          pbVar26 = *(byte **)(puVar40 + 0x30);
        } while (uVar43 < *(ulonglong *)(puVar40 + 0x50));
        pbVar18 = *(byte **)(puVar40 + 0x48);
      }
      if (((pbVar18[9] != 0) && (DAT_1400132b0 != 0)) && (DAT_1400132b8 != (longlong *)0x0)) {
        *pbVar18 = *pbVar18 ^ DAT_1400130c7;
        pbVar18[1] = pbVar18[1] ^ DAT_1400130c7;
        pbVar18[2] = pbVar18[2] ^ DAT_1400130c7;
        pbVar18[3] = pbVar18[3] ^ DAT_1400130c7;
        pbVar18[4] = pbVar18[4] ^ DAT_1400130c7;
        pbVar18[5] = pbVar18[5] ^ DAT_1400130c7;
        pbVar18[6] = pbVar18[6] ^ DAT_1400130c7;
        pbVar18[7] = pbVar18[7] ^ DAT_1400130c7;
        uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar18[8] * 8);
        *(undefined8 *)(puVar40 + 0x20) = uVar2;
        puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
        puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
        puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
        puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
        puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
        puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
        puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
        puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
        uVar2 = *(undefined8 *)(pbVar18 + 0x12);
        uVar3 = *(undefined8 *)pbVar18;
        *(undefined8 *)(puVar40 + -8) = 0x140008058;
        DAT_140013201 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
        pbVar18[9] = pbVar18[9] == 0;
        *pbVar18 = *pbVar18 ^ DAT_1400130c7;
        pbVar18[1] = pbVar18[1] ^ DAT_1400130c7;
        pbVar18[2] = pbVar18[2] ^ DAT_1400130c7;
        pbVar18[3] = pbVar18[3] ^ DAT_1400130c7;
        pbVar18[4] = pbVar18[4] ^ DAT_1400130c7;
        pbVar18[5] = pbVar18[5] ^ DAT_1400130c7;
        pbVar18[6] = pbVar18[6] ^ DAT_1400130c7;
        pbVar18[7] = pbVar18[7] ^ DAT_1400130c7;
      }
    }
LAB_1400080b7:
    uVar43 = 0;
    if (0xf < local_e0) {
      pvVar20 = (void *)CONCAT71(uStack_f7,local_f8);
      pvVar23 = pvVar20;
      if ((0xfff < local_e0 + 1) &&
         (pvVar23 = *(void **)((longlong)pvVar20 + -8),
         0x1f < (ulonglong)((longlong)pvVar20 + (-8 - (longlong)pvVar23)))) goto LAB_14000828c;
      *(undefined8 *)(puVar40 + -8) = 0x1400080f8;
      free(pvVar23);
    }
    pppppbVar25 = (byte *****)local_118;
    piVar41 = local_1d8;
    uVar39 = DAT_140013be0;
    local_e8 = (byte *)0x0;
    local_e0 = 0xf;
    local_f8 = 0;
    pppppbVar36 = &local_128;
    if (0xf < local_110) {
      pppppbVar36 = (byte *****)local_128;
    }
    *(byte ******)(puVar40 + 0x38) = pppppbVar36;
    pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    uVar31 = uVar43;
    if (DAT_14001321a == '\0') {
      do {
        (&DAT_1400133d0)[uVar31] = ~DAT_1400130b8 ^ (ulonglong)pbVar48 ^ uVar39;
        DAT_1400130b8 = DAT_1400130b8 - 0xffffffff;
        uVar31 = uVar31 + 1;
      } while (uVar31 != 0x100);
      DAT_14001321a = '\x01';
      pppppbVar36 = *(byte ******)(puVar40 + 0x38);
    }
    *(ulonglong *)(puVar40 + 0x20) = uVar39;
    if ((byte *****)local_118 != (byte *****)0x0) {
      do {
        bVar16 = *(byte *)((longlong)pppppbVar36 + (longlong)(int)uVar43);
        puVar40[0x20] = (byte)uVar39 ^ bVar16;
        puVar40[0x21] = puVar40[0x21] ^ bVar16;
        puVar40[0x22] = puVar40[0x22] ^ bVar16;
        puVar40[0x23] = puVar40[0x23] ^ bVar16;
        puVar40[0x24] = puVar40[0x24] ^ bVar16;
        puVar40[0x25] = puVar40[0x25] ^ bVar16;
        puVar40[0x26] = puVar40[0x26] ^ bVar16;
        puVar40[0x27] = puVar40[0x27] ^ bVar16;
        uVar39 = *(ulonglong *)(puVar40 + 0x20) ^ (&DAT_1400133d0)[(byte)~bVar16];
        *(ulonglong *)(puVar40 + 0x20) = uVar39;
        uVar17 = (int)uVar43 + 1;
        uVar43 = (ulonglong)uVar17;
      } while ((byte *****)(longlong)(int)uVar17 < local_118);
    }
    if (*local_1d8 < DAT_140013c50) {
      *(undefined8 *)(puVar40 + -8) = 0x140008217;
      FUN_14000e96c(&DAT_140013c50);
      if (DAT_140013c50 == -1) {
        *(undefined8 *)(puVar40 + -8) = 0x140008233;
        _DAT_140013c48 = uVar39;
        _Init_thread_footer(&DAT_140013c50);
      }
      pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    }
    if (*piVar41 < DAT_140013c40) {
      *(undefined8 *)(puVar40 + -8) = 0x140008250;
      FUN_14000e96c(&DAT_140013c40);
      if (DAT_140013c40 == -1) {
        _DAT_140013c38 = CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
        *(undefined8 *)(puVar40 + -8) = 0x140008273;
        _Init_thread_footer(&DAT_140013c40);
      }
      pbVar48 = (byte *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
    }
    uVar43 = (ulonglong)*(byte *)pppppbVar36;
    bVar16 = DAT_140013bd0;
    if ((byte *****)0x1 < pppppbVar25) {
      bVar16 = ((byte *)((longlong)pppppbVar25 + -1))[(longlong)pppppbVar36];
    }
  }
  else {
    pvVar20 = (void *)CONCAT71(uStack_f7,local_f8);
    pvVar23 = pvVar20;
    if ((local_e0 + 1 < 0x1000) ||
       (pvVar23 = *(void **)((longlong)pvVar20 + -8),
       (ulonglong)((longlong)pvVar20 + (-8 - (longlong)pvVar23)) < 0x20)) {
      *(undefined8 *)(puVar40 + -8) = 0x140006c68;
      free(pvVar23);
      goto LAB_140006c68;
    }
LAB_14000828c:
    uVar43 = 0;
    pcVar49 = (code *)swi(0x29);
    (*pcVar49)(5);
    puVar40 = puVar40 + 8;
    bVar16 = DAT_140013bd0;
  }
  *(byte ******)(puVar40 + 0x28) = pppppbVar25;
  *(byte ******)(puVar40 + 0x30) = pppppbVar25;
  uVar17 = 0;
  bVar28 = (byte)pppppbVar25;
  bVar33 = bVar28;
  do {
    bVar28 = bVar28 ^ (byte)uVar43;
    bVar33 = bVar33 ^ bVar16;
    uVar17 = uVar17 + 1;
  } while (uVar17 < 8);
  puVar40[0x28] = bVar28;
  puVar40[0x30] = bVar33;
  uVar39 = (longlong)pppppbVar25 * 8;
  bVar50 = DAT_140013200 == '\0';
  _DAT_140013c38 = (ulonglong)pppppbVar25 ^ (ulonglong)pbVar48 ^ _DAT_140013c38;
  puVar40[0x20] = puVar40[0x20] ^ (byte)_DAT_140013c38;
  lVar30 = *(longlong *)(puVar40 + 0x28);
  lVar1 = *(longlong *)(puVar40 + 0x30);
  lVar27 = lVar30;
  if (bVar50) {
    lVar27 = lVar1;
  }
  uVar31 = *(ulonglong *)(puVar40 + 0x20);
  *(ulonglong *)(puVar40 + 0x20) = uVar31 ^ lVar27 << 0x38;
  uVar46 = (ulonglong)pppppbVar25 ^ _DAT_140013c38 ^ (ulonglong)pbVar48;
  puVar40[0x21] = (byte)(uVar46 >> 8) ^ (byte)(uVar31 >> 8);
  lVar27 = lVar30;
  if (!bVar50) {
    lVar27 = lVar1;
  }
  uVar31 = *(ulonglong *)(puVar40 + 0x20);
  *(ulonglong *)(puVar40 + 0x20) = uVar31 ^ lVar27 << 0x38;
  bVar33 = (byte)uVar39;
  uVar46 = (longlong)pppppbVar25 << (bVar33 & 0xf) ^ uVar46 ^ (ulonglong)pbVar48;
  puVar40[0x22] = (byte)(uVar31 >> 0x10) ^ (byte)(uVar46 >> 0x10);
  lVar27 = lVar30;
  if (bVar50) {
    lVar27 = lVar1;
  }
  uVar31 = *(ulonglong *)(puVar40 + 0x20);
  *(ulonglong *)(puVar40 + 0x20) = uVar31 ^ lVar27 << 0x30;
  uVar46 = (longlong)pppppbVar25 << (bVar33 + (char)(uVar39 / 0x18) * -0x18 & 0x3f) ^ uVar46 ^
           (ulonglong)pbVar48;
  puVar40[0x23] = (byte)(uVar46 >> 0x18) ^ (byte)(uVar31 >> 0x18);
  lVar27 = lVar30;
  if (!bVar50) {
    lVar27 = lVar1;
  }
  uVar31 = *(ulonglong *)(puVar40 + 0x20);
  *(ulonglong *)(puVar40 + 0x20) = uVar31 ^ lVar27 << 0x28;
  uVar46 = (longlong)pppppbVar25 << (bVar33 & 0x1f) ^ uVar46 ^ (ulonglong)pbVar48;
  puVar40[0x24] = (byte)(uVar31 >> 0x20) ^ (byte)(uVar46 >> 0x20);
  lVar27 = lVar30;
  if (bVar50) {
    lVar27 = lVar1;
  }
  uVar31 = *(ulonglong *)(puVar40 + 0x20);
  *(ulonglong *)(puVar40 + 0x20) = uVar31 ^ lVar27 << 0x20;
  uVar46 = (longlong)pppppbVar25 << (bVar33 + (char)(uVar39 / 0x28) * -0x28 & 0x3f) ^ uVar46 ^
           (ulonglong)pbVar48;
  puVar40[0x25] = (byte)((uVar31 ^ lVar27 << 0x20) >> 0x28) ^ (byte)(uVar46 >> 0x28);
  lVar27 = lVar30;
  if (!bVar50) {
    lVar27 = lVar1;
  }
  uVar31 = *(ulonglong *)(puVar40 + 0x20);
  *(ulonglong *)(puVar40 + 0x20) = uVar31 ^ lVar27 << 0x18;
  uVar46 = (longlong)pppppbVar25 << (bVar33 + (char)(uVar39 / 0x30) * -0x30 & 0x3f) ^ uVar46 ^
           (ulonglong)pbVar48;
  puVar40[0x26] = (byte)((uVar31 ^ lVar27 << 0x18) >> 0x30) ^ (byte)(uVar46 >> 0x30);
  lVar27 = lVar30;
  if (bVar50) {
    lVar27 = lVar1;
  }
  uVar31 = *(ulonglong *)(puVar40 + 0x20);
  *(ulonglong *)(puVar40 + 0x20) = uVar31 ^ lVar27 << 0x10;
  auVar11._8_8_ = 0;
  auVar11._0_8_ = uVar39;
  lVar35 = SUB168(ZEXT816(0x2492492492492493) * auVar11,8);
  puVar40[0x27] =
       (byte)((ulonglong)
              ((longlong)pppppbVar25 <<
              (bVar33 + (char)((uVar39 - lVar35 >> 1) + lVar35 >> 5) * -0x38 & 0x3f)) >> 0x38) ^
       (byte)((uVar31 ^ lVar27 << 0x10) >> 0x38) ^ (byte)(uVar46 >> 0x38) ^ DAT_140013be8._7_1_;
  if (!bVar50) {
    lVar30 = lVar1;
  }
  local_108 = DAT_140013bd8 + uVar43 * -0x80 + (ulonglong)bVar16 * -0xff ^ lVar30 << 8 ^
              *(ulonglong *)(puVar40 + 0x20) ^ _DAT_140013c48;
  uVar43 = 0;
  _DAT_140013c48 = 0;
  _DAT_140013c38 = 0;
  DAT_140013200 = '\0';
  local_100 = 0;
  pppppcVar32 = &local_88;
  if (0xf < local_70) {
    pppppcVar32 = (char *****)local_88;
  }
  *(undefined8 *)(puVar40 + -8) = 0x1400085a4;
  pbVar24 = FUN_14000d860(local_1e0,(char *)pppppcVar32,local_78);
  *(undefined8 *)(puVar40 + -8) = 0x1400085b4;
  std::basic_ostream<>::operator<<(pbVar24,FUN_14000d310);
  if (0xf < local_70) {
    pppppcVar32 = (char *****)local_88;
    if ((0xfff < local_70 + 1) &&
       (pppppcVar32 = (char *****)local_88[-1],
       (char *)0x1f < (char *)((longlong)local_88 + (-8 - (longlong)pppppcVar32))))
    goto LAB_14000d2fa;
    *(undefined8 *)(puVar40 + -8) = 0x1400085f5;
    free(pppppcVar32);
  }
  pcVar49 = cin_exref;
  uStack_80 = 0;
  local_78 = 0;
  local_70 = 0xf;
  local_88 = (char ****)0x0;
  iVar34 = *(int *)(*(longlong *)cin_exref + 4);
  *(undefined8 *)(puVar40 + -8) = 0x14000864a;
  bVar16 = std::basic_ios<>::widen((basic_ios<> *)(cin_exref + iVar34),'\n');
  *(undefined8 *)(puVar40 + -8) = 0x14000865d;
  FUN_14000da30((basic_istream<> *)pcVar49,(longlong *)&local_88,(ulonglong)bVar16);
  pppppcVar32 = &local_88;
  if (0xf < local_70) {
    pppppcVar32 = (char *****)local_88;
  }
  if (local_78 == 4) {
    *(undefined8 *)(puVar40 + -8) = 0x140008691;
    iVar34 = memcmp(pppppcVar32,&DAT_140010580,4);
    if (iVar34 == 0) {
      local_1c0 = 0x3367363d5a215235;
      local_1b8 = CONCAT26(local_1b8._6_2_,0x57832603d61);
      local_1d0 = (void *)0x4c5f497b66746370;
      uStack_1c8 = 0x444e31575f335630;
      lVar30 = 0x10;
      do {
        *(byte *)((longlong)&local_1d0 + lVar30) = *(byte *)((longlong)&local_1d0 + lVar30) ^ 5;
        lVar30 = lVar30 + 1;
      } while (lVar30 != 0x1e);
      uStack_d0 = 0;
      local_c8 = 0;
      local_c0 = 0xf;
      local_d8 = (byte ****)0x0;
      *(undefined8 *)(puVar40 + -8) = 0x140008737;
      pppppbVar25 = (byte *****)FUN_14000d620(&local_198,(char *)&local_1d0);
      *(byte ******)(puVar40 + 0x48) = pppppbVar25;
      if (&local_d8 != pppppbVar25) {
        pppppbVar36 = pppppbVar25;
        if ((byte ****)0xf < pppppbVar25[3]) {
          pppppbVar36 = (byte *****)*pppppbVar25;
        }
        ppppbVar4 = pppppbVar25[2];
        *(undefined8 *)(puVar40 + -8) = 0x14000876a;
        FUN_14000e130((longlong *)&local_d8,pppppbVar36,(size_t)ppppbVar4);
      }
      sVar14 = local_c8;
      *(size_t *)(puVar40 + 0x58) = local_c8;
      pppppbVar36 = &local_d8;
      if (0xf < local_c0) {
        pppppbVar36 = (byte *****)local_d8;
      }
      if (DAT_140013219 == '\0') {
        *(undefined8 *)(puVar40 + -8) = 0x14000879b;
        FUN_140001c90();
      }
      if ((pppppbVar36 != (byte *****)0x0) && (sVar14 != 0)) {
        *(undefined8 *)(puVar40 + -8) = 0x1400087b8;
        pbVar26 = FUN_140003190((longlong)pppppbVar36,sVar14);
        plVar21 = DAT_1400132b8;
        *(byte **)(puVar40 + 0x30) = pbVar26;
        if (pbVar26[9] == 0) {
          if ((DAT_1400132b0 == 0) || (DAT_1400132b8 == (longlong *)0x0)) {
            cVar15 = '\0';
          }
          else {
            *pbVar26 = *pbVar26 ^ DAT_1400130c7;
            pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
            pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
            pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
            pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
            pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
            pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
            pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
            uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar26[8] * 8);
            *(undefined8 *)(puVar40 + 0x20) = uVar2;
            puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
            puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
            puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
            puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
            puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
            puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
            puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
            puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
            uVar2 = *(undefined8 *)(pbVar26 + 0x12);
            uVar3 = *(undefined8 *)pbVar26;
            *(undefined8 *)(puVar40 + -8) = 0x14000887f;
            cVar15 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
            DAT_140013201 = cVar15;
            pbVar26[9] = pbVar26[9] == 0;
            *pbVar26 = *pbVar26 ^ DAT_1400130c7;
            pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
            pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
            pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
            pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
            pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
            pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
            pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
          }
          if (cVar15 == '\0') goto LAB_14000972d;
        }
        plVar21 = DAT_1400132b8;
        if (sVar14 != 0) {
          uVar39 = (ulonglong)DAT_14001321c;
          local_1e0 = (basic_ostream<> *)(&DAT_1400132c0 + uVar39);
          *(ulonglong *)(puVar40 + 0x38) = uVar39 * 8 + 0x1400132c1;
          local_1e8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_1f0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_1f8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_200 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_208 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_210 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_14001321d;
          local_218 = (byte *)(&DAT_1400132c0 + uVar39);
          local_220 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
          local_228 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_230 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_238 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_240 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_248 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_250 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_14001321e;
          local_258 = (byte *)(&DAT_1400132c0 + uVar39);
          local_260 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
          local_268 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_270 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_278 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_280 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_288 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_290 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_14001321f;
          local_298 = (byte *)(&DAT_1400132c0 + uVar39);
          local_2a0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
          local_2a8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_2b0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_2b8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_2c0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_2c8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_2d0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          lVar30 = (ulonglong)DAT_1400133c0 * 8;
          local_2d8 = (byte *)(&DAT_140013340 + DAT_1400133c0);
          local_2e0 = (byte *)((longlong)&DAT_140013340 + lVar30 + 1);
          lVar1 = (ulonglong)DAT_1400133c1 * 8;
          local_2e8 = (byte *)(&DAT_140013340 + DAT_1400133c1);
          local_2f0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
          pbVar26 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
          *(byte **)(puVar40 + 0x50) = pbVar26;
          *(longlong *)(puVar40 + 0x28) = lVar1 + 0x140013344;
          local_2f8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
          local_300 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
          local_308 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
          lVar27 = (ulonglong)DAT_1400133c2 * 8;
          local_310 = (byte *)(&DAT_140013340 + DAT_1400133c2);
          local_318 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_320 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_328 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_330 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_338 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_340 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_348 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          lVar27 = (ulonglong)DAT_1400133c3 * 8;
          local_350 = (byte *)(&DAT_140013340 + DAT_1400133c3);
          local_358 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_360 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_368 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_370 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_378 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_380 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_388 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          lVar27 = (ulonglong)DAT_1400133c4 * 8;
          local_390 = (byte *)(&DAT_140013340 + DAT_1400133c4);
          local_398 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_3a0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_3a8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_3b0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_3b8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_3c0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_3c8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          lVar27 = (ulonglong)DAT_1400133c5 * 8;
          local_3d0 = (byte *)(&DAT_140013340 + DAT_1400133c5);
          local_3d8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_3e0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_3e8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_3f0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_3f8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_400 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_408 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          uVar39 = (ulonglong)DAT_1400133c6;
          local_410 = (byte *)(&DAT_140013340 + uVar39);
          local_418 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 1);
          local_420 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 2);
          local_428 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 3);
          local_430 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 4);
          local_438 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 5);
          local_440 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 6);
          local_448 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_1400133c7;
          local_450 = (byte *)(&DAT_140013340 + uVar39);
          local_458 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 1);
          local_460 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 2);
          local_468 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 3);
          *(ulonglong *)(puVar40 + 0x78) = uVar39 * 8 + 0x140013344;
          *(ulonglong *)(puVar40 + 0x70) = uVar39 * 8 + 0x140013345;
          *(ulonglong *)(puVar40 + 0x68) = uVar39 * 8 + 0x140013346;
          *(ulonglong *)(puVar40 + 0x60) = uVar39 * 8 + 0x140013347;
          pppppbVar25 = pppppbVar36;
          do {
            *(byte *)((longlong)pppppbVar36 + uVar43) =
                 *(byte *)((longlong)pppppbVar36 + uVar43) ^ (byte)*local_1e0;
            bVar33 = *(byte *)((longlong)pppppbVar36 + uVar43);
            bVar16 = **(byte **)(puVar40 + 0x38);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar33 ^ bVar16;
            bVar16 = bVar33 ^ bVar16 ^ *local_1e8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_1f0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_1f8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_200;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_208;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_210;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_218;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_220;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_228;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_230;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_238;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_240;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_248;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_250;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_258;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_260;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_268;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_270;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_278;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_280;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_288;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_290;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_298;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2a0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2a8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2b0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2b8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2c0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2c8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2d0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2d8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2e0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 2);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 3);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 4);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 5);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 6);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 7);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2e8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2f0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar1 + 2);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *pbVar26;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x28);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2f8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_300;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_308;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_310;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_318;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_320;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_328;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_330;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_338;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_340;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_348;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_350;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_358;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_360;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_368;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_370;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_378;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_380;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_388;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_390;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_398;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3a0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3a8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3b0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3b8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3c0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3c8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3d0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3d8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3e0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3e8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3f0;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3f8;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_400;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_408;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_410;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_418;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_420;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_428;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_430;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_438;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_440;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_448;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)(&DAT_140013340 + uVar39);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_458;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_460;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_468;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x78);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x70);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x68);
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16;
            *(byte *)((longlong)pppppbVar36 + uVar43) = bVar16 ^ **(byte **)(puVar40 + 0x60);
            uVar31 = 0;
            do {
              uVar46 = (ulonglong)(byte)(&DAT_140013220)[uVar31];
              bVar33 = *(byte *)(&DAT_140013230 + uVar46);
              bVar16 = *(byte *)pppppbVar25;
              *(byte *)pppppbVar25 = bVar33 ^ bVar16;
              bVar16 = bVar33 ^ bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 1);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 2);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 3);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 4);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 5);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 6);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 7);
              *(byte *)pppppbVar25 = bVar16;
              uVar46 = (ulonglong)(byte)(&DAT_140013221)[uVar31];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar46);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 1);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 2);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 3);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 4);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 5);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 6);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 7);
              *(byte *)pppppbVar25 = bVar16;
              uVar46 = (ulonglong)(byte)(&DAT_140013222)[uVar31];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar46);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 1);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 2);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 3);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 4);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 5);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 6);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 7);
              *(byte *)pppppbVar25 = bVar16;
              uVar46 = (ulonglong)(byte)(&DAT_140013223)[uVar31];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar46);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 1);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 2);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 3);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 4);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 5);
              *(byte *)pppppbVar25 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 6);
              *(byte *)pppppbVar25 = bVar16;
              *(byte *)pppppbVar25 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar46 * 8 + 7);
              uVar31 = uVar31 + 4;
            } while (uVar31 < 0xc);
            uVar43 = uVar43 + 1;
            pppppbVar25 = (byte *****)((longlong)pppppbVar25 + 1);
            pbVar26 = *(byte **)(puVar40 + 0x50);
          } while (uVar43 < *(ulonglong *)(puVar40 + 0x58));
          pbVar26 = *(byte **)(puVar40 + 0x30);
          pppppbVar25 = *(byte ******)(puVar40 + 0x48);
        }
        if (((pbVar26[9] != 0) && (DAT_1400132b0 != 0)) && (DAT_1400132b8 != (longlong *)0x0)) {
          *pbVar26 = *pbVar26 ^ DAT_1400130c7;
          pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
          pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
          pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
          pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
          pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
          pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
          pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
          uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar26[8] * 8);
          *(undefined8 *)(puVar40 + 0x20) = uVar2;
          puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
          puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
          puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
          puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
          puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
          puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
          puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
          puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
          uVar2 = *(undefined8 *)(pbVar26 + 0x12);
          uVar3 = *(undefined8 *)pbVar26;
          *(undefined8 *)(puVar40 + -8) = 0x1400096ce;
          DAT_140013201 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
          pbVar26[9] = pbVar26[9] == 0;
          *pbVar26 = *pbVar26 ^ DAT_1400130c7;
          pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
          pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
          pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
          pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
          pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
          pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
          pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
        }
      }
LAB_14000972d:
      uVar43 = 0;
      if ((byte ****)0xf < pppppbVar25[3]) {
        ppppbVar4 = *pppppbVar25;
        _Memory = ppppbVar4;
        if ((0xfff < (longlong)pppppbVar25[3] + 1U) &&
           (_Memory = (byte ****)ppppbVar4[-1],
           0x1f < (ulonglong)((longlong)ppppbVar4 + (-8 - (longlong)_Memory)))) {
          pcVar49 = (code *)swi(0x29);
          _Memory = (byte ****)(*pcVar49)(5);
          puVar40 = puVar40 + 8;
        }
        *(undefined8 *)(puVar40 + -8) = 0x14000976c;
        free(_Memory);
      }
      sVar14 = local_c8;
      pppppbVar25[2] = (byte ****)0x0;
      pppppbVar25[3] = (byte ****)0xf;
      *(undefined1 *)pppppbVar25 = 0;
      *(size_t *)(puVar40 + 0x58) = local_c8;
      pppppbVar25 = &local_d8;
      if (0xf < local_c0) {
        pppppbVar25 = (byte *****)local_d8;
      }
      if (DAT_140013219 == '\0') {
        *(undefined8 *)(puVar40 + -8) = 0x1400097ac;
        FUN_140001c90();
      }
      if ((pppppbVar25 != (byte *****)0x0) && (sVar14 != 0)) {
        *(undefined8 *)(puVar40 + -8) = 0x1400097c9;
        pbVar26 = FUN_140003190((longlong)pppppbVar25,sVar14);
        plVar21 = DAT_1400132b8;
        *(byte **)(puVar40 + 0x30) = pbVar26;
        if (pbVar26[9] == 0) {
          if ((DAT_1400132b0 == 0) || (DAT_1400132b8 == (longlong *)0x0)) {
            cVar15 = '\0';
          }
          else {
            *pbVar26 = *pbVar26 ^ DAT_1400130c7;
            pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
            pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
            pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
            pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
            pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
            pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
            pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
            uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar26[8] * 8);
            *(undefined8 *)(puVar40 + 0x20) = uVar2;
            puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
            puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
            puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
            puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
            puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
            puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
            puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
            puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
            uVar2 = *(undefined8 *)(pbVar26 + 0x12);
            uVar3 = *(undefined8 *)pbVar26;
            *(undefined8 *)(puVar40 + -8) = 0x140009890;
            cVar15 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
            DAT_140013201 = cVar15;
            pbVar26[9] = pbVar26[9] == 0;
            *pbVar26 = *pbVar26 ^ DAT_1400130c7;
            pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
            pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
            pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
            pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
            pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
            pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
            pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
          }
          if (cVar15 == '\0') goto LAB_14000a731;
        }
        plVar21 = DAT_1400132b8;
        if (sVar14 != 0) {
          uVar39 = (ulonglong)DAT_14001321c;
          local_1e0 = (basic_ostream<> *)(&DAT_1400132c0 + uVar39);
          *(ulonglong *)(puVar40 + 0x38) = uVar39 * 8 + 0x1400132c1;
          local_1e8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_1f0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_1f8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_200 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_208 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_210 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_14001321d;
          local_218 = (byte *)(&DAT_1400132c0 + uVar39);
          local_220 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
          local_228 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_230 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_238 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_240 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_248 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_250 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_14001321e;
          local_258 = (byte *)(&DAT_1400132c0 + uVar39);
          local_260 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
          local_268 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_270 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_278 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_280 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_288 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_290 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          lVar30 = (ulonglong)DAT_14001321f * 8;
          local_298 = (byte *)(&DAT_1400132c0 + DAT_14001321f);
          lVar1 = (ulonglong)DAT_1400133c0 * 8;
          local_2a0 = (byte *)(&DAT_140013340 + DAT_1400133c0);
          local_2a8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
          pbVar26 = (byte *)((longlong)&DAT_140013340 + lVar1 + 2);
          *(byte **)(puVar40 + 0x50) = pbVar26;
          *(longlong *)(puVar40 + 0x28) = lVar1 + 0x140013343;
          local_2b0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 4);
          local_2b8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
          local_2c0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
          local_2c8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
          lVar1 = (ulonglong)DAT_1400133c1 * 8;
          local_2d0 = (byte *)(&DAT_140013340 + DAT_1400133c1);
          local_2d8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
          local_2e0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 2);
          local_2e8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
          local_2f0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 4);
          local_2f8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
          local_300 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
          local_308 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
          lVar1 = (ulonglong)DAT_1400133c2 * 8;
          local_310 = (byte *)(&DAT_140013340 + DAT_1400133c2);
          local_318 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
          local_320 = (byte *)((longlong)&DAT_140013340 + lVar1 + 2);
          local_328 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
          local_330 = (byte *)((longlong)&DAT_140013340 + lVar1 + 4);
          local_338 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
          local_340 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
          local_348 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
          lVar1 = (ulonglong)DAT_1400133c3 * 8;
          local_350 = (byte *)(&DAT_140013340 + DAT_1400133c3);
          local_358 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
          local_360 = (byte *)((longlong)&DAT_140013340 + lVar1 + 2);
          local_368 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
          local_370 = (byte *)((longlong)&DAT_140013340 + lVar1 + 4);
          local_378 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
          local_380 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
          local_388 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
          lVar1 = (ulonglong)DAT_1400133c4 * 8;
          local_390 = (byte *)(&DAT_140013340 + DAT_1400133c4);
          local_398 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
          local_3a0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 2);
          local_3a8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
          local_3b0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 4);
          local_3b8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
          local_3c0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
          local_3c8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
          lVar1 = (ulonglong)DAT_1400133c5 * 8;
          local_3d0 = (byte *)(&DAT_140013340 + DAT_1400133c5);
          local_3d8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
          local_3e0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 2);
          local_3e8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
          local_3f0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 4);
          local_3f8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
          local_400 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
          local_408 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
          lVar1 = (ulonglong)DAT_1400133c6 * 8;
          local_410 = (byte *)(&DAT_140013340 + DAT_1400133c6);
          local_418 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
          local_420 = (byte *)((longlong)&DAT_140013340 + lVar1 + 2);
          local_428 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
          local_430 = (byte *)((longlong)&DAT_140013340 + lVar1 + 4);
          local_438 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
          local_440 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
          local_448 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
          uVar39 = (ulonglong)DAT_1400133c7;
          local_450 = (byte *)(&DAT_140013340 + uVar39);
          local_458 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 1);
          local_460 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 2);
          local_468 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 3);
          *(ulonglong *)(puVar40 + 0x78) = uVar39 * 8 + 0x140013344;
          *(ulonglong *)(puVar40 + 0x70) = uVar39 * 8 + 0x140013345;
          *(ulonglong *)(puVar40 + 0x68) = uVar39 * 8 + 0x140013346;
          *(ulonglong *)(puVar40 + 0x60) = uVar39 * 8 + 0x140013347;
          pppppbVar36 = pppppbVar25;
          do {
            *(byte *)((longlong)pppppbVar25 + uVar43) =
                 *(byte *)((longlong)pppppbVar25 + uVar43) ^ (byte)*local_1e0;
            bVar33 = *(byte *)((longlong)pppppbVar25 + uVar43);
            bVar16 = **(byte **)(puVar40 + 0x38);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar33 ^ bVar16;
            bVar16 = bVar33 ^ bVar16 ^ *local_1e8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_1f0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_1f8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_200;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_208;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_210;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_218;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_220;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_228;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_230;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_238;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_240;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_248;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_250;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_258;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_260;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_268;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_270;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_278;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_280;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_288;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_290;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_298;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_1400132c0 + lVar30 + 1);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_1400132c0 + lVar30 + 2);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_1400132c0 + lVar30 + 3);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_1400132c0 + lVar30 + 4);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_1400132c0 + lVar30 + 5);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_1400132c0 + lVar30 + 6);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_1400132c0 + lVar30 + 7);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2a0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2a8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *pbVar26;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x28);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2b0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2b8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2c0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2c8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2d0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2d8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2e0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2e8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2f0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2f8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_300;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_308;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_310;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_318;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_320;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_328;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_330;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_338;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_340;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_348;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_350;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_358;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_360;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_368;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_370;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_378;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_380;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_388;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_390;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_398;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3a0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3a8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3b0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3b8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3c0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3c8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3d0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3d8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3e0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3e8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3f0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3f8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_400;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_408;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_410;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_418;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_420;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_428;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_430;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_438;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_440;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_448;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_450;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_458;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_460;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_468;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x78);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x70);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x68);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16 ^ **(byte **)(puVar40 + 0x60);
            uVar39 = 0;
            do {
              uVar31 = (ulonglong)(byte)(&DAT_140013220)[uVar39];
              bVar33 = *(byte *)(&DAT_140013230 + uVar31);
              bVar16 = *(byte *)pppppbVar36;
              *(byte *)pppppbVar36 = bVar33 ^ bVar16;
              bVar16 = bVar33 ^ bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              *(byte *)pppppbVar36 = bVar16;
              uVar31 = (ulonglong)(byte)(&DAT_140013221)[uVar39];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              *(byte *)pppppbVar36 = bVar16;
              uVar31 = (ulonglong)(byte)(&DAT_140013222)[uVar39];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              *(byte *)pppppbVar36 = bVar16;
              uVar31 = (ulonglong)(byte)(&DAT_140013223)[uVar39];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              *(byte *)pppppbVar36 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              uVar39 = uVar39 + 4;
            } while (uVar39 < 0xc);
            uVar43 = uVar43 + 1;
            pppppbVar36 = (byte *****)((longlong)pppppbVar36 + 1);
            pbVar26 = *(byte **)(puVar40 + 0x50);
          } while (uVar43 < *(ulonglong *)(puVar40 + 0x58));
          pbVar26 = *(byte **)(puVar40 + 0x30);
        }
        if (((pbVar26[9] != 0) && (DAT_1400132b0 != 0)) && (DAT_1400132b8 != (longlong *)0x0)) {
          *pbVar26 = *pbVar26 ^ DAT_1400130c7;
          pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
          pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
          pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
          pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
          pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
          pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
          pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
          uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar26[8] * 8);
          *(undefined8 *)(puVar40 + 0x20) = uVar2;
          puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
          puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
          puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
          puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
          puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
          puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
          puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
          puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
          uVar2 = *(undefined8 *)(pbVar26 + 0x12);
          uVar3 = *(undefined8 *)pbVar26;
          *(undefined8 *)(puVar40 + -8) = 0x14000a6d2;
          DAT_140013201 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
          pbVar26[9] = pbVar26[9] == 0;
          *pbVar26 = *pbVar26 ^ DAT_1400130c7;
          pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
          pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
          pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
          pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
          pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
          pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
          pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
        }
      }
LAB_14000a731:
      uVar43 = 0;
      *(undefined8 *)(puVar40 + -8) = 0x14000a744;
      FUN_14000d740((undefined8 *)&local_f8,&local_d8);
      sVar14 = local_c8;
      *(size_t *)(puVar40 + 0x58) = local_c8;
      pppppbVar25 = &local_d8;
      if (0xf < local_c0) {
        pppppbVar25 = (byte *****)local_d8;
      }
      if (DAT_140013219 == '\0') {
        *(undefined8 *)(puVar40 + -8) = 0x14000a775;
        FUN_140001c90();
      }
      if ((pppppbVar25 != (byte *****)0x0) && (sVar14 != 0)) {
        *(undefined8 *)(puVar40 + -8) = 0x14000a792;
        pbVar26 = FUN_140003190((longlong)pppppbVar25,sVar14);
        plVar21 = DAT_1400132b8;
        *(byte **)(puVar40 + 0x30) = pbVar26;
        if (pbVar26[9] == 0) {
          if ((DAT_1400132b0 == 0) || (DAT_1400132b8 == (longlong *)0x0)) {
            cVar15 = '\0';
          }
          else {
            *pbVar26 = *pbVar26 ^ DAT_1400130c7;
            pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
            pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
            pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
            pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
            pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
            pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
            pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
            uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar26[8] * 8);
            *(undefined8 *)(puVar40 + 0x20) = uVar2;
            puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
            puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
            puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
            puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
            puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
            puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
            puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
            puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
            uVar2 = *(undefined8 *)(pbVar26 + 0x12);
            uVar3 = *(undefined8 *)pbVar26;
            *(undefined8 *)(puVar40 + -8) = 0x14000a859;
            cVar15 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
            DAT_140013201 = cVar15;
            pbVar26[9] = pbVar26[9] == 0;
            *pbVar26 = *pbVar26 ^ DAT_1400130c7;
            pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
            pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
            pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
            pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
            pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
            pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
            pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
          }
          if (cVar15 == '\0') goto LAB_14000b6e1;
        }
        plVar21 = DAT_1400132b8;
        if (sVar14 != 0) {
          uVar39 = (ulonglong)DAT_14001321c;
          local_1e0 = (basic_ostream<> *)(&DAT_1400132c0 + uVar39);
          *(ulonglong *)(puVar40 + 0x38) = uVar39 * 8 + 0x1400132c1;
          local_1e8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_1f0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_1f8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_200 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_208 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_210 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_14001321d;
          local_218 = (byte *)(&DAT_1400132c0 + uVar39);
          local_220 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
          local_228 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_230 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_238 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_240 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_248 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_250 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_14001321e;
          local_258 = (byte *)(&DAT_1400132c0 + uVar39);
          local_260 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
          local_268 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_270 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_278 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_280 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_288 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_290 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_14001321f;
          local_298 = (byte *)(&DAT_1400132c0 + uVar39);
          local_2a0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
          local_2a8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_2b0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_2b8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_2c0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_2c8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_2d0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          lVar30 = (ulonglong)DAT_1400133c0 * 8;
          local_2d8 = (byte *)(&DAT_140013340 + DAT_1400133c0);
          local_2e0 = (byte *)((longlong)&DAT_140013340 + lVar30 + 1);
          lVar1 = (ulonglong)DAT_1400133c1 * 8;
          local_2e8 = (byte *)(&DAT_140013340 + DAT_1400133c1);
          local_2f0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
          pbVar26 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
          *(byte **)(puVar40 + 0x50) = pbVar26;
          *(longlong *)(puVar40 + 0x28) = lVar1 + 0x140013344;
          local_2f8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
          local_300 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
          local_308 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
          lVar27 = (ulonglong)DAT_1400133c2 * 8;
          local_310 = (byte *)(&DAT_140013340 + DAT_1400133c2);
          local_318 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_320 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_328 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_330 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_338 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_340 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_348 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          lVar27 = (ulonglong)DAT_1400133c3 * 8;
          local_350 = (byte *)(&DAT_140013340 + DAT_1400133c3);
          local_358 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_360 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_368 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_370 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_378 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_380 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_388 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          lVar27 = (ulonglong)DAT_1400133c4 * 8;
          local_390 = (byte *)(&DAT_140013340 + DAT_1400133c4);
          local_398 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_3a0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_3a8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_3b0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_3b8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_3c0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_3c8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          uVar39 = (ulonglong)DAT_1400133c5;
          local_3d0 = (byte *)(&DAT_140013340 + uVar39);
          local_3d8 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 1);
          local_3e0 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 2);
          local_3e8 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 3);
          local_3f0 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 4);
          local_3f8 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 5);
          local_400 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 6);
          local_408 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 7);
          lVar27 = (ulonglong)DAT_1400133c6 * 8;
          local_410 = (byte *)(&DAT_140013340 + DAT_1400133c6);
          local_418 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_420 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_428 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_430 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_438 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_440 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_448 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          lVar27 = (ulonglong)DAT_1400133c7 * 8;
          local_450 = (byte *)(&DAT_140013340 + DAT_1400133c7);
          local_458 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_460 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_468 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          *(longlong *)(puVar40 + 0x78) = lVar27 + 0x140013344;
          *(longlong *)(puVar40 + 0x70) = lVar27 + 0x140013345;
          *(longlong *)(puVar40 + 0x68) = lVar27 + 0x140013346;
          *(longlong *)(puVar40 + 0x60) = lVar27 + 0x140013347;
          pppppbVar36 = pppppbVar25;
          do {
            *(byte *)((longlong)pppppbVar25 + uVar43) =
                 *(byte *)((longlong)pppppbVar25 + uVar43) ^ (byte)*local_1e0;
            bVar33 = *(byte *)((longlong)pppppbVar25 + uVar43);
            bVar16 = **(byte **)(puVar40 + 0x38);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar33 ^ bVar16;
            bVar16 = bVar33 ^ bVar16 ^ *local_1e8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_1f0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_1f8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_200;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_208;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_210;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_218;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_220;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_228;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_230;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_238;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_240;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_248;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_250;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_258;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_260;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_268;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_270;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_278;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_280;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_288;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_290;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_298;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2a0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2a8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2b0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2b8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2c0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2c8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2d0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2d8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2e0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 2);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 3);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 4);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 5);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 6);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 7);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2e8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2f0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar1 + 2);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *pbVar26;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x28);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2f8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_300;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_308;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_310;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_318;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_320;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_328;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_330;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_338;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_340;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_348;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_350;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_358;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_360;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_368;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_370;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_378;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_380;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_388;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_390;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_398;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3a0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3a8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3b0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3b8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3c0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3c8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3d0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3d8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3e0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3e8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3f0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3f8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_400;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_408;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_410;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_418;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_420;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_428;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_430;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_438;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_440;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_448;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_450;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_458;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_460;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_468;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x78);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x70);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x68);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16 ^ **(byte **)(puVar40 + 0x60);
            uVar39 = 0;
            do {
              uVar31 = (ulonglong)(byte)(&DAT_140013220)[uVar39];
              bVar33 = *(byte *)(&DAT_140013230 + uVar31);
              bVar16 = *(byte *)pppppbVar36;
              *(byte *)pppppbVar36 = bVar33 ^ bVar16;
              bVar16 = bVar33 ^ bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              *(byte *)pppppbVar36 = bVar16;
              uVar31 = (ulonglong)(byte)(&DAT_140013221)[uVar39];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              *(byte *)pppppbVar36 = bVar16;
              uVar31 = (ulonglong)(byte)(&DAT_140013222)[uVar39];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              *(byte *)pppppbVar36 = bVar16;
              uVar31 = (ulonglong)(byte)(&DAT_140013223)[uVar39];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              *(byte *)pppppbVar36 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              uVar39 = uVar39 + 4;
            } while (uVar39 < 0xc);
            uVar43 = uVar43 + 1;
            pppppbVar36 = (byte *****)((longlong)pppppbVar36 + 1);
            pbVar26 = *(byte **)(puVar40 + 0x50);
          } while (uVar43 < *(ulonglong *)(puVar40 + 0x58));
          pbVar26 = *(byte **)(puVar40 + 0x30);
        }
        if (((pbVar26[9] != 0) && (DAT_1400132b0 != 0)) && (DAT_1400132b8 != (longlong *)0x0)) {
          *pbVar26 = *pbVar26 ^ DAT_1400130c7;
          pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
          pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
          pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
          pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
          pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
          pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
          pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
          uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar26[8] * 8);
          *(undefined8 *)(puVar40 + 0x20) = uVar2;
          puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
          puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
          puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
          puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
          puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
          puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
          puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
          puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
          uVar2 = *(undefined8 *)(pbVar26 + 0x12);
          uVar3 = *(undefined8 *)pbVar26;
          *(undefined8 *)(puVar40 + -8) = 0x14000b682;
          DAT_140013201 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
          pbVar26[9] = pbVar26[9] == 0;
          *pbVar26 = *pbVar26 ^ DAT_1400130c7;
          pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
          pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
          pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
          pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
          pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
          pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
          pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
        }
      }
LAB_14000b6e1:
      uVar43 = DAT_140013be0;
      uVar39 = 0;
      uStack_b0 = 0;
      local_a8 = 0;
      local_a0 = 0xf;
      local_b8 = (byte ****)0x0;
      pcVar49 = FUN_140003760;
      if (DAT_140013218 == '\0') {
        DAT_140013210 = FUN_140003760;
        DAT_140013218 = '\x01';
      }
      uStack_1c8 = 0;
      local_1c0 = 0;
      local_1b8 = 0xf;
      local_1d0 = (void *)0x0;
      uVar46 = 0xffffffff;
      uVar31 = uVar39;
      if (DAT_14001321a == '\0') {
        do {
          (&DAT_1400133d0)[uVar31] =
               ~DAT_1400130b8 ^ CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8) ^ uVar43;
          DAT_1400130b8 = DAT_1400130b8 - 0xffffffff;
          uVar31 = uVar31 + 1;
        } while (uVar31 != 0x100);
        DAT_14001321a = '\x01';
      }
      *(ulonglong *)(puVar40 + 0x20) = uVar43;
                    /* WARNING: Load size is inaccurate */
      lVar30 = *ThreadLocalStoragePointer;
      uVar31 = 4;
      if (*(int *)(lVar30 + 4) < DAT_140013c50) {
        *(undefined8 *)(puVar40 + -8) = 0x14000b7d4;
        FUN_14000e96c(&DAT_140013c50);
        if (DAT_140013c50 == -1) {
          _DAT_140013c48 = uVar43;
          *(undefined8 *)(puVar40 + -8) = 0x14000b7f0;
          _Init_thread_footer(&DAT_140013c50);
        }
      }
      if (*(int *)(lVar30 + 4) < DAT_140013c40) {
        *(undefined8 *)(puVar40 + -8) = 0x14000b808;
        FUN_14000e96c(&DAT_140013c40);
        if (DAT_140013c40 == -1) {
          _DAT_140013c38 = CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
          *(undefined8 *)(puVar40 + -8) = 0x14000b82b;
          _Init_thread_footer(&DAT_140013c40);
        }
      }
      *(undefined8 *)(puVar40 + 0x28) = 0;
      bVar16 = 0;
      uVar43 = uVar39;
      do {
        bVar16 = bVar16 ^ DAT_140013bd0;
        uVar17 = (int)uVar43 + 1;
        uVar43 = (ulonglong)uVar17;
      } while (uVar17 < 8);
      puVar40[0x28] = bVar16;
      bVar50 = DAT_140013200 == '\0';
      _DAT_140013c38 = CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8) ^ _DAT_140013c38;
      puVar40[0x20] = puVar40[0x20] ^ (byte)_DAT_140013c38;
      uVar43 = *(ulonglong *)(puVar40 + 0x28);
      uVar44 = uVar39;
      if (bVar50) {
        uVar44 = uVar43;
      }
      uVar19 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar19 ^ uVar44 << 0x38;
      puVar40[0x21] =
           (byte)(uVar19 >> 8) ^
           (byte)(_DAT_140013c38 >> 8) ^ (byte)((uint7)(undefined7)DAT_140013be8 >> 8);
      uVar44 = uVar39;
      if (!bVar50) {
        uVar44 = uVar43;
      }
      uVar19 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar19 ^ uVar44 << 0x38;
      puVar40[0x22] = (byte)(uVar19 >> 0x10) ^ (byte)(_DAT_140013c38 >> 0x10);
      uVar44 = uVar39;
      if (bVar50) {
        uVar44 = uVar43;
      }
      uVar19 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar19 ^ uVar44 << 0x30;
      puVar40[0x23] =
           (byte)(uVar19 >> 0x18) ^
           (byte)((uint7)(undefined7)DAT_140013be8 >> 0x18) ^ (byte)(_DAT_140013c38 >> 0x18);
      uVar44 = uVar39;
      if (!bVar50) {
        uVar44 = uVar43;
      }
      uVar19 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar19 ^ uVar44 << 0x28;
      puVar40[0x24] = (byte)(uVar19 >> 0x20) ^ (byte)(_DAT_140013c38 >> 0x20);
      uVar44 = uVar39;
      if (bVar50) {
        uVar44 = uVar43;
      }
      uVar19 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar19 ^ uVar44 << 0x20;
      puVar40[0x25] =
           (byte)((uVar19 ^ uVar44 << 0x20) >> 0x28) ^
           (byte)((uint7)(undefined7)DAT_140013be8 >> 0x28) ^ (byte)(_DAT_140013c38 >> 0x28);
      uVar44 = uVar39;
      if (!bVar50) {
        uVar44 = uVar43;
      }
      uVar19 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar19 ^ uVar44 << 0x18;
      puVar40[0x26] = (byte)((uVar19 ^ uVar44 << 0x18) >> 0x30) ^ (byte)(_DAT_140013c38 >> 0x30);
      uVar44 = uVar39;
      if (bVar50) {
        uVar44 = uVar43;
      }
      uVar19 = *(ulonglong *)(puVar40 + 0x20);
      *(ulonglong *)(puVar40 + 0x20) = uVar19 ^ uVar44 << 0x10;
      puVar40[0x27] =
           (byte)((uVar19 ^ uVar44 << 0x10) >> 0x38) ^ DAT_140013be8._7_1_ ^
           (byte)(_DAT_140013c38 >> 0x38);
      uVar44 = uVar39;
      if (!bVar50) {
        uVar44 = uVar43;
      }
      local_98 = DAT_140013bd8 + (ulonglong)DAT_140013bd0 * -0xff ^ uVar44 << 8 ^
                 *(ulonglong *)(puVar40 + 0x20) ^ _DAT_140013c48;
      _DAT_140013c48 = 0;
      _DAT_140013c38 = 0;
      DAT_140013200 = '\0';
      *(undefined8 *)(puVar40 + -8) = 0x14000ba32;
      FUN_14000e130((longlong *)&local_b8,&local_1d0,0);
      if (local_1b8 < 0x10) {
LAB_14000ba74:
        if ((DAT_14001321b == '\0') && (DAT_140013218 == '\0')) {
          DAT_140013210 = FUN_140003760;
          DAT_140013218 = '\x01';
          DAT_14001321b = '\x01';
        }
        local_190 = 0;
        *(undefined8 *)(puVar40 + -8) = 0x14000baac;
        local_198 = (char *)operator_new(0x50);
        local_188 = 0x41;
        local_180 = 0x4f;
        builtin_strncpy(local_198,
                        "Thank you! I think i wrote it down somewhere .... Ahh, here it is",0x42);
        local_90 = '\x01';
        *(undefined8 *)(puVar40 + -8) = 0x14000bb1e;
        FUN_14000e130((longlong *)&local_b8,local_198,0x41);
        uVar31 = local_a8;
        uVar43 = DAT_140013be0;
        if (local_90 == '\0') {
          pppppbVar25 = &local_b8;
          if (0xf < local_a0) {
            pppppbVar25 = (byte *****)local_b8;
          }
          pcVar49 = (code *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
          uVar46 = uVar39;
          if (DAT_14001321a == '\0') {
            do {
              (&DAT_1400133d0)[uVar46] = ~DAT_1400130b8 ^ (ulonglong)pcVar49 ^ uVar43;
              DAT_1400130b8 = DAT_1400130b8 - 0xffffffff;
              uVar46 = uVar46 + 1;
            } while (uVar46 != 0x100);
            DAT_14001321a = '\x01';
          }
          *(ulonglong *)(puVar40 + 0x20) = uVar43;
          if (local_a8 != 0) {
            do {
              bVar16 = *(byte *)((longlong)pppppbVar25 + (longlong)(int)uVar39);
              puVar40[0x20] = bVar16 ^ (byte)uVar43;
              puVar40[0x21] = puVar40[0x21] ^ bVar16;
              puVar40[0x22] = puVar40[0x22] ^ bVar16;
              puVar40[0x23] = puVar40[0x23] ^ bVar16;
              puVar40[0x24] = puVar40[0x24] ^ bVar16;
              puVar40[0x25] = puVar40[0x25] ^ bVar16;
              puVar40[0x26] = puVar40[0x26] ^ bVar16;
              puVar40[0x27] = puVar40[0x27] ^ bVar16;
              uVar43 = *(ulonglong *)(puVar40 + 0x20) ^ (&DAT_1400133d0)[(byte)~bVar16];
              *(ulonglong *)(puVar40 + 0x20) = uVar43;
              uVar17 = (int)uVar39 + 1;
              uVar39 = (ulonglong)uVar17;
            } while ((ulonglong)(longlong)(int)uVar17 < local_a8);
          }
                    /* WARNING: Load size is inaccurate */
          lVar30 = *ThreadLocalStoragePointer;
          if (*(int *)(lVar30 + 4) < DAT_140013c50) {
            *(undefined8 *)(puVar40 + -8) = 0x14000bc27;
            FUN_14000e96c(&DAT_140013c50);
            if (DAT_140013c50 == -1) {
              *(undefined8 *)(puVar40 + -8) = 0x14000bc43;
              _DAT_140013c48 = uVar43;
              _Init_thread_footer(&DAT_140013c50);
            }
            pcVar49 = (code *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
          }
          if (*(int *)(lVar30 + 4) < DAT_140013c40) {
            *(undefined8 *)(puVar40 + -8) = 0x14000bc62;
            FUN_14000e96c(&DAT_140013c40);
            if (DAT_140013c40 == -1) {
              _DAT_140013c38 = CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
              *(undefined8 *)(puVar40 + -8) = 0x14000bc85;
              _Init_thread_footer(&DAT_140013c40);
            }
            pcVar49 = (code *)CONCAT17(DAT_140013be8._7_1_,(undefined7)DAT_140013be8);
          }
          uVar46 = (ulonglong)*(byte *)pppppbVar25;
          bVar16 = DAT_140013bd0;
          if (1 < uVar31) {
            bVar16 = *(byte *)((longlong)pppppbVar25 + (uVar31 - 1));
          }
          goto LAB_14000bcad;
        }
      }
      else {
        pvVar23 = local_1d0;
        if ((local_1b8 + 1 < 0x1000) ||
           (pvVar23 = *(void **)((longlong)local_1d0 + -8),
           (ulonglong)((longlong)local_1d0 + (-8 - (longlong)pvVar23)) < 0x20)) {
          *(undefined8 *)(puVar40 + -8) = 0x14000ba73;
          free(pvVar23);
          goto LAB_14000ba74;
        }
        pcVar5 = (code *)swi(0x29);
        (*pcVar5)(5);
        puVar40 = puVar40 + 8;
        bVar16 = DAT_140013bd0;
LAB_14000bcad:
        pcVar5 = DAT_140013210;
        *(ulonglong *)(puVar40 + 0x28) = uVar31;
        *(ulonglong *)(puVar40 + 0x30) = uVar31;
        uVar17 = 0;
        bVar28 = (byte)uVar31;
        bVar33 = bVar28;
        do {
          bVar28 = bVar28 ^ (byte)uVar46;
          bVar33 = bVar33 ^ bVar16;
          uVar17 = uVar17 + 1;
        } while (uVar17 < 8);
        puVar40[0x28] = bVar28;
        puVar40[0x30] = bVar33;
        uVar43 = uVar31 * 8;
        bVar50 = DAT_140013200 == '\0';
        _DAT_140013c38 = uVar31 ^ (ulonglong)pcVar49 ^ _DAT_140013c38;
        puVar40[0x20] = puVar40[0x20] ^ (byte)_DAT_140013c38;
        lVar30 = *(longlong *)(puVar40 + 0x28);
        lVar1 = *(longlong *)(puVar40 + 0x30);
        lVar27 = lVar30;
        if (bVar50) {
          lVar27 = lVar1;
        }
        uVar39 = *(ulonglong *)(puVar40 + 0x20);
        *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x38;
        uVar44 = _DAT_140013c38 ^ uVar31 ^ (ulonglong)pcVar49;
        puVar40[0x21] = (byte)(uVar39 >> 8) ^ (byte)(uVar44 >> 8);
        lVar27 = lVar30;
        if (!bVar50) {
          lVar27 = lVar1;
        }
        uVar39 = *(ulonglong *)(puVar40 + 0x20);
        *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x38;
        bVar33 = (byte)uVar43;
        uVar44 = uVar31 << (bVar33 & 0xf) ^ uVar44 ^ (ulonglong)pcVar49;
        puVar40[0x22] = (byte)(uVar44 >> 0x10) ^ (byte)(uVar39 >> 0x10);
        lVar27 = lVar30;
        if (bVar50) {
          lVar27 = lVar1;
        }
        uVar39 = *(ulonglong *)(puVar40 + 0x20);
        *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x30;
        uVar44 = uVar31 << (bVar33 + (char)(uVar43 / 0x18) * -0x18 & 0x3f) ^ uVar44 ^
                 (ulonglong)pcVar49;
        puVar40[0x23] = (byte)(uVar39 >> 0x18) ^ (byte)(uVar44 >> 0x18);
        lVar27 = lVar30;
        if (!bVar50) {
          lVar27 = lVar1;
        }
        uVar39 = *(ulonglong *)(puVar40 + 0x20);
        *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x28;
        uVar44 = uVar31 << (bVar33 & 0x1f) ^ uVar44 ^ (ulonglong)pcVar49;
        puVar40[0x24] = (byte)(uVar39 >> 0x20) ^ (byte)(uVar44 >> 0x20);
        lVar27 = lVar30;
        if (bVar50) {
          lVar27 = lVar1;
        }
        uVar39 = *(ulonglong *)(puVar40 + 0x20);
        *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x20;
        uVar44 = uVar31 << (bVar33 + (char)(uVar43 / 0x28) * -0x28 & 0x3f) ^ uVar44 ^
                 (ulonglong)pcVar49;
        puVar40[0x25] = (byte)(uVar44 >> 0x28) ^ (byte)((uVar39 ^ lVar27 << 0x20) >> 0x28);
        lVar27 = lVar30;
        if (!bVar50) {
          lVar27 = lVar1;
        }
        uVar39 = *(ulonglong *)(puVar40 + 0x20);
        *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x18;
        uVar44 = uVar31 << (bVar33 + (char)(uVar43 / 0x30) * -0x30 & 0x3f) ^ uVar44 ^
                 (ulonglong)pcVar49;
        puVar40[0x26] = (byte)(uVar44 >> 0x30) ^ (byte)((uVar39 ^ lVar27 << 0x18) >> 0x30);
        lVar27 = lVar30;
        if (bVar50) {
          lVar27 = lVar1;
        }
        uVar39 = *(ulonglong *)(puVar40 + 0x20);
        *(ulonglong *)(puVar40 + 0x20) = uVar39 ^ lVar27 << 0x10;
        auVar12._8_8_ = 0;
        auVar12._0_8_ = uVar43;
        lVar35 = SUB168(ZEXT816(0x2492492492492493) * auVar12,8);
        puVar40[0x27] =
             (byte)((uVar31 <<
                    (bVar33 + (char)((uVar43 - lVar35 >> 1) + lVar35 >> 5) * -0x38 & 0x3f)) >> 0x38)
             ^ (byte)(uVar44 >> 0x38) ^ (byte)((uVar39 ^ lVar27 << 0x10) >> 0x38) ^
             DAT_140013be8._7_1_;
        if (!bVar50) {
          lVar30 = lVar1;
        }
        uVar43 = DAT_140013bd8 + uVar46 * -0x80 + (ulonglong)bVar16 * -0xff ^ lVar30 << 8 ^
                 *(ulonglong *)(puVar40 + 0x20) ^ _DAT_140013c48;
        _DAT_140013c48 = 0;
        _DAT_140013c38 = 0;
        DAT_140013200 = '\0';
        if (uVar43 != local_98) {
          *(undefined8 *)(puVar40 + -8) = 0x14000bf9d;
          plVar21 = FUN_140003640(local_160,local_98,uVar43);
          *(undefined8 *)(puVar40 + -8) = 0x14000bfa9;
          (*pcVar5)(plVar21,&local_b8);
        }
      }
      uVar43 = 0;
      *(undefined8 *)(puVar40 + -8) = 0x14000bfbc;
      FUN_14000d740(&local_1d0,&local_b8);
      lVar30 = local_1c0;
      *(longlong *)(puVar40 + 0x58) = local_1c0;
      local_90 = '\x01';
      pppppbVar25 = &local_b8;
      if (0xf < local_a0) {
        pppppbVar25 = (byte *****)local_b8;
      }
      if (DAT_140013219 == '\0') {
        *(undefined8 *)(puVar40 + -8) = 0x14000bff5;
        FUN_140001c90();
      }
      if ((pppppbVar25 != (byte *****)0x0) && (lVar30 != 0)) {
        *(undefined8 *)(puVar40 + -8) = 0x14000c012;
        pbVar26 = FUN_140003190((longlong)pppppbVar25,lVar30);
        plVar21 = DAT_1400132b8;
        *(byte **)(puVar40 + 0x30) = pbVar26;
        if (pbVar26[9] == 0) {
          if ((DAT_1400132b0 == 0) || (DAT_1400132b8 == (longlong *)0x0)) {
            cVar15 = '\0';
          }
          else {
            *pbVar26 = *pbVar26 ^ DAT_1400130c7;
            pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
            pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
            pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
            pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
            pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
            pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
            pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
            uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar26[8] * 8);
            *(undefined8 *)(puVar40 + 0x20) = uVar2;
            puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
            puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
            puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
            puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
            puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
            puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
            puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
            puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
            uVar2 = *(undefined8 *)(pbVar26 + 0x12);
            uVar3 = *(undefined8 *)pbVar26;
            *(undefined8 *)(puVar40 + -8) = 0x14000c0d9;
            cVar15 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
            DAT_140013201 = cVar15;
            pbVar26[9] = pbVar26[9] == 0;
            *pbVar26 = *pbVar26 ^ DAT_1400130c7;
            pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
            pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
            pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
            pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
            pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
            pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
            pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
          }
          if (cVar15 == '\0') goto LAB_14000cf61;
        }
        plVar21 = DAT_1400132b8;
        if (lVar30 != 0) {
          uVar39 = (ulonglong)DAT_14001321c;
          local_1e0 = (basic_ostream<> *)(&DAT_1400132c0 + uVar39);
          *(ulonglong *)(puVar40 + 0x38) = uVar39 * 8 + 0x1400132c1;
          local_1e8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_1f0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_1f8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_200 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_208 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_210 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_14001321d;
          local_218 = (byte *)(&DAT_1400132c0 + uVar39);
          local_220 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
          local_228 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_230 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_238 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_240 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_248 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_250 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_14001321e;
          local_258 = (byte *)(&DAT_1400132c0 + uVar39);
          local_260 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
          local_268 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_270 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_278 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_280 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_288 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_290 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          uVar39 = (ulonglong)DAT_14001321f;
          local_298 = (byte *)(&DAT_1400132c0 + uVar39);
          local_2a0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 1);
          local_2a8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 2);
          local_2b0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 3);
          local_2b8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 4);
          local_2c0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 5);
          local_2c8 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 6);
          local_2d0 = (byte *)((longlong)&DAT_1400132c0 + uVar39 * 8 + 7);
          lVar30 = (ulonglong)DAT_1400133c0 * 8;
          local_2d8 = (byte *)(&DAT_140013340 + DAT_1400133c0);
          local_2e0 = (byte *)((longlong)&DAT_140013340 + lVar30 + 1);
          lVar1 = (ulonglong)DAT_1400133c1 * 8;
          local_2e8 = (byte *)(&DAT_140013340 + DAT_1400133c1);
          local_2f0 = (byte *)((longlong)&DAT_140013340 + lVar1 + 1);
          pbVar26 = (byte *)((longlong)&DAT_140013340 + lVar1 + 3);
          *(byte **)(puVar40 + 0x50) = pbVar26;
          *(longlong *)(puVar40 + 0x28) = lVar1 + 0x140013344;
          local_2f8 = (byte *)((longlong)&DAT_140013340 + lVar1 + 5);
          local_300 = (byte *)((longlong)&DAT_140013340 + lVar1 + 6);
          local_308 = (byte *)((longlong)&DAT_140013340 + lVar1 + 7);
          lVar27 = (ulonglong)DAT_1400133c2 * 8;
          local_310 = (byte *)(&DAT_140013340 + DAT_1400133c2);
          local_318 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_320 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_328 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_330 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_338 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_340 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_348 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          lVar27 = (ulonglong)DAT_1400133c3 * 8;
          local_350 = (byte *)(&DAT_140013340 + DAT_1400133c3);
          local_358 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_360 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_368 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_370 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_378 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_380 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_388 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          lVar27 = (ulonglong)DAT_1400133c4 * 8;
          local_390 = (byte *)(&DAT_140013340 + DAT_1400133c4);
          local_398 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_3a0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_3a8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_3b0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_3b8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_3c0 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_3c8 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          uVar39 = (ulonglong)DAT_1400133c5;
          local_3d0 = (byte *)(&DAT_140013340 + uVar39);
          local_3d8 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 1);
          local_3e0 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 2);
          local_3e8 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 3);
          local_3f0 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 4);
          local_3f8 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 5);
          local_400 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 6);
          local_408 = (byte *)((longlong)&DAT_140013340 + uVar39 * 8 + 7);
          lVar27 = (ulonglong)DAT_1400133c6 * 8;
          local_410 = (byte *)(&DAT_140013340 + DAT_1400133c6);
          local_418 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_420 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_428 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          local_430 = (byte *)((longlong)&DAT_140013340 + lVar27 + 4);
          local_438 = (byte *)((longlong)&DAT_140013340 + lVar27 + 5);
          local_440 = (byte *)((longlong)&DAT_140013340 + lVar27 + 6);
          local_448 = (byte *)((longlong)&DAT_140013340 + lVar27 + 7);
          lVar27 = (ulonglong)DAT_1400133c7 * 8;
          local_450 = (byte *)(&DAT_140013340 + DAT_1400133c7);
          local_458 = (byte *)((longlong)&DAT_140013340 + lVar27 + 1);
          local_460 = (byte *)((longlong)&DAT_140013340 + lVar27 + 2);
          local_468 = (byte *)((longlong)&DAT_140013340 + lVar27 + 3);
          *(longlong *)(puVar40 + 0x78) = lVar27 + 0x140013344;
          *(longlong *)(puVar40 + 0x70) = lVar27 + 0x140013345;
          *(longlong *)(puVar40 + 0x68) = lVar27 + 0x140013346;
          *(longlong *)(puVar40 + 0x60) = lVar27 + 0x140013347;
          pppppbVar36 = pppppbVar25;
          do {
            *(byte *)((longlong)pppppbVar25 + uVar43) =
                 *(byte *)((longlong)pppppbVar25 + uVar43) ^ (byte)*local_1e0;
            bVar33 = *(byte *)((longlong)pppppbVar25 + uVar43);
            bVar16 = **(byte **)(puVar40 + 0x38);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar33 ^ bVar16;
            bVar16 = bVar33 ^ bVar16 ^ *local_1e8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_1f0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_1f8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_200;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_208;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_210;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_218;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_220;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_228;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_230;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_238;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_240;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_248;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_250;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_258;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_260;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_268;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_270;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_278;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_280;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_288;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_290;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_298;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2a0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2a8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2b0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2b8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2c0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2c8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2d0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2d8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2e0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 2);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 3);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 4);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 5);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 6);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar30 + 7);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2e8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2f0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013340 + lVar1 + 2);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *pbVar26;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x28);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_2f8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_300;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_308;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_310;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_318;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_320;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_328;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_330;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_338;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_340;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_348;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_350;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_358;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_360;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_368;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_370;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_378;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_380;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_388;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_390;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_398;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3a0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3a8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3b0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3b8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3c0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3c8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3d0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3d8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3e0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3e8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3f0;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_3f8;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_400;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_408;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_410;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_418;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_420;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_428;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_430;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_438;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_440;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_448;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_450;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_458;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_460;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ *local_468;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x78);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x70);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            bVar16 = bVar16 ^ **(byte **)(puVar40 + 0x68);
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16;
            *(byte *)((longlong)pppppbVar25 + uVar43) = bVar16 ^ **(byte **)(puVar40 + 0x60);
            uVar39 = 0;
            do {
              uVar31 = (ulonglong)(byte)(&DAT_140013220)[uVar39];
              bVar33 = *(byte *)(&DAT_140013230 + uVar31);
              bVar16 = *(byte *)pppppbVar36;
              *(byte *)pppppbVar36 = bVar33 ^ bVar16;
              bVar16 = bVar33 ^ bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              *(byte *)pppppbVar36 = bVar16;
              uVar31 = (ulonglong)(byte)(&DAT_140013221)[uVar39];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              *(byte *)pppppbVar36 = bVar16;
              uVar31 = (ulonglong)(byte)(&DAT_140013222)[uVar39];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              *(byte *)pppppbVar36 = bVar16;
              uVar31 = (ulonglong)(byte)(&DAT_140013223)[uVar39];
              bVar16 = bVar16 ^ *(byte *)(&DAT_140013230 + uVar31);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 1);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 2);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 3);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 4);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 5);
              *(byte *)pppppbVar36 = bVar16;
              bVar16 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 6);
              *(byte *)pppppbVar36 = bVar16;
              *(byte *)pppppbVar36 = bVar16 ^ *(byte *)((longlong)&DAT_140013230 + uVar31 * 8 + 7);
              uVar39 = uVar39 + 4;
            } while (uVar39 < 0xc);
            uVar43 = uVar43 + 1;
            pppppbVar36 = (byte *****)((longlong)pppppbVar36 + 1);
            pbVar26 = *(byte **)(puVar40 + 0x50);
          } while (uVar43 < *(ulonglong *)(puVar40 + 0x58));
          pbVar26 = *(byte **)(puVar40 + 0x30);
        }
        if (((pbVar26[9] != 0) && (DAT_1400132b0 != 0)) && (DAT_1400132b8 != (longlong *)0x0)) {
          *pbVar26 = *pbVar26 ^ DAT_1400130c7;
          pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
          pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
          pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
          pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
          pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
          pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
          pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
          uVar2 = *(undefined8 *)(*plVar21 + (ulonglong)pbVar26[8] * 8);
          *(undefined8 *)(puVar40 + 0x20) = uVar2;
          puVar40[0x20] = (byte)uVar2 ^ DAT_1400130c7;
          puVar40[0x21] = puVar40[0x21] ^ DAT_1400130c7;
          puVar40[0x22] = puVar40[0x22] ^ DAT_1400130c7;
          puVar40[0x23] = puVar40[0x23] ^ DAT_1400130c7;
          puVar40[0x24] = puVar40[0x24] ^ DAT_1400130c7;
          puVar40[0x25] = puVar40[0x25] ^ DAT_1400130c7;
          puVar40[0x26] = puVar40[0x26] ^ DAT_1400130c7;
          puVar40[0x27] = puVar40[0x27] ^ DAT_1400130c7;
          uVar2 = *(undefined8 *)(pbVar26 + 0x12);
          uVar3 = *(undefined8 *)pbVar26;
          *(undefined8 *)(puVar40 + -8) = 0x14000cf02;
          DAT_140013201 = (**(code **)(puVar40 + 0x20))(uVar3,uVar2);
          pbVar26[9] = pbVar26[9] == 0;
          *pbVar26 = *pbVar26 ^ DAT_1400130c7;
          pbVar26[1] = pbVar26[1] ^ DAT_1400130c7;
          pbVar26[2] = pbVar26[2] ^ DAT_1400130c7;
          pbVar26[3] = pbVar26[3] ^ DAT_1400130c7;
          pbVar26[4] = pbVar26[4] ^ DAT_1400130c7;
          pbVar26[5] = pbVar26[5] ^ DAT_1400130c7;
          pbVar26[6] = pbVar26[6] ^ DAT_1400130c7;
          pbVar26[7] = pbVar26[7] ^ DAT_1400130c7;
        }
      }
LAB_14000cf61:
      if (0xf < local_1b8) {
        pvVar23 = local_1d0;
        if ((local_1b8 + 1 < 0x1000) ||
           (pvVar23 = *(void **)((longlong)local_1d0 + -8),
           (ulonglong)((longlong)local_1d0 + (-8 - (longlong)pvVar23)) < 0x20)) {
          *(undefined8 *)(puVar40 + -8) = 0x14000cfa2;
          free(pvVar23);
          goto LAB_14000cfa2;
        }
LAB_14000d2f3:
        pcVar49 = (code *)swi(0x29);
        (*pcVar49)(5);
        goto LAB_14000d2fa;
      }
LAB_14000cfa2:
      local_1c0 = 0;
      local_1b8 = 0xf;
      local_1d0 = (void *)((ulonglong)local_1d0 & 0xffffffffffffff00);
      if (0xf < local_180) {
        _Memory_00 = local_198;
        if ((0xfff < local_180 + 1) &&
           (_Memory_00 = *(char **)(local_198 + -8),
           (char *)0x1f < local_198 + (-8 - (longlong)_Memory_00))) goto LAB_14000d2f3;
        *(undefined8 *)(puVar40 + -8) = 0x14000cffc;
        free(_Memory_00);
      }
      *(undefined8 *)(puVar40 + -8) = 0x14000d009;
      pbVar24 = FUN_14000d350((basic_ostream<> *)cout_exref);
      puVar38 = &local_f8;
      if (0xf < local_e0) {
        puVar38 = (undefined1 *)CONCAT71(uStack_f7,local_f8);
      }
      *(undefined8 *)(puVar40 + -8) = 0x14000d029;
      pbVar24 = std::basic_ostream<>::operator<<(pbVar24,puVar38);
      *(undefined8 *)(puVar40 + -8) = 0x14000d039;
      std::basic_ostream<>::operator<<(pbVar24,FUN_14000d310);
      local_90 = 1;
      pppppbVar25 = &local_b8;
      if (0xf < local_a0) {
        pppppbVar25 = (byte *****)local_b8;
      }
      *(undefined8 *)(puVar40 + -8) = 0x14000d05c;
      FUN_140002f60((longlong)pppppbVar25);
      pppppbVar25 = &local_b8;
      if (0xf < local_a0) {
        pppppbVar25 = (byte *****)local_b8;
      }
      *(undefined8 *)(puVar40 + -8) = 0x14000d081;
      memset(pppppbVar25,0,local_a8);
      local_98 = 0;
      local_90 = '\0';
      if (0xf < local_a0) {
        pppppbVar25 = (byte *****)local_b8;
        if ((0xfff < local_a0 + 1) &&
           (pppppbVar25 = (byte *****)local_b8[-1],
           (byte *)0x1f < (byte *)((longlong)local_b8 + (-8 - (longlong)pppppbVar25))))
        goto LAB_14000d2fa;
        *(undefined8 *)(puVar40 + -8) = 0x14000d0d1;
        free(pppppbVar25);
      }
      local_a8 = 0;
      local_a0 = 0xf;
      local_b8 = (byte ****)((ulonglong)local_b8 & 0xffffffffffffff00);
      if (0xf < local_e0) {
        pvVar20 = (void *)CONCAT71(uStack_f7,local_f8);
        pvVar23 = pvVar20;
        if ((0xfff < local_e0 + 1) &&
           (pvVar23 = *(void **)((longlong)pvVar20 + -8),
           0x1f < (ulonglong)((longlong)pvVar20 + (-8 - (longlong)pvVar23)))) goto LAB_14000d2fa;
        *(undefined8 *)(puVar40 + -8) = 0x14000d12b;
        free(pvVar23);
      }
      local_e8 = (byte *)0x0;
      local_e0 = 0xf;
      local_f8 = 0;
      pppppbVar25 = &local_d8;
      if (0xf < local_c0) {
        pppppbVar25 = (byte *****)local_d8;
      }
      *(undefined8 *)(puVar40 + -8) = 0x14000d160;
      FUN_140002f60((longlong)pppppbVar25);
      pppppbVar25 = &local_d8;
      if (0xf < local_c0) {
        pppppbVar25 = (byte *****)local_d8;
      }
      *(undefined8 *)(puVar40 + -8) = 0x14000d185;
      memset(pppppbVar25,0,local_c8);
      if (0xf < local_c0) {
        pppppbVar25 = (byte *****)local_d8;
        if ((0xfff < local_c0 + 1) &&
           (pppppbVar25 = (byte *****)local_d8[-1],
           (byte *)0x1f < (byte *)((longlong)local_d8 + (-8 - (longlong)pppppbVar25))))
        goto LAB_14000d2fa;
        *(undefined8 *)(puVar40 + -8) = 0x14000d1c6;
        free(pppppbVar25);
      }
    }
  }
  pcVar49 = cin_exref;
  iVar34 = *(int *)(*(longlong *)cin_exref + 4);
  *(undefined8 *)(puVar40 + -8) = 0x14000d1df;
  bVar16 = std::basic_ios<>::widen((basic_ios<> *)(cin_exref + iVar34),'\n');
  *(undefined8 *)(puVar40 + -8) = 0x14000d1f2;
  FUN_14000da30((basic_istream<> *)pcVar49,(longlong *)&local_88,(ulonglong)bVar16);
  *(undefined8 *)(puVar40 + -8) = 0x14000d1f7;
  FUN_140003880();
  if (0xf < local_70) {
    pppppcVar32 = (char *****)local_88;
    if ((0xfff < local_70 + 1) &&
       (pppppcVar32 = (char *****)local_88[-1],
       (char *)0x1f < (char *)((longlong)local_88 + (-8 - (longlong)pppppcVar32))))
    goto LAB_14000d2fa;
    *(undefined8 *)(puVar40 + -8) = 0x14000d23a;
    free(pppppcVar32);
  }
  local_100 = 1;
  pppppbVar25 = &local_128;
  if (0xf < local_110) {
    pppppbVar25 = (byte *****)local_128;
  }
  *(undefined8 *)(puVar40 + -8) = 0x14000d25d;
  FUN_140002f60((longlong)pppppbVar25);
  pppppbVar25 = &local_128;
  if (0xf < local_110) {
    pppppbVar25 = (byte *****)local_128;
  }
  *(undefined8 *)(puVar40 + -8) = 0x14000d282;
  memset(pppppbVar25,0,(size_t)local_118);
  local_108 = 0;
  local_100 = 0;
  if (0xf < local_110) {
    pppppbVar25 = (byte *****)local_128;
    if ((0xfff < local_110 + 1) &&
       (pppppbVar25 = (byte *****)local_128[-1],
       (byte *)0x1f < (byte *)((longlong)local_128 + (-8 - (longlong)pppppbVar25)))) {
LAB_14000d2fa:
      pcVar49 = (code *)swi(0x29);
      (*pcVar49)(5);
      pcVar49 = (code *)swi(3);
      (*pcVar49)();
      return;
    }
    *(undefined8 *)(puVar40 + -8) = 0x14000d2ce;
    free(pppppbVar25);
  }
  *(undefined8 *)(puVar40 + -8) = 0x14000d2df;
  FUN_14000e8e0(local_50 ^ (ulonglong)puVar40);
  return;
}
```


### 1. Xác định hàm chính (Main Logic)
Hàm quan trọng nhất trong đoạn code này là `FUN_140003890`. Đây là nơi chứa logic chính của chương trình: in ra thông báo, nhận input và kiểm tra.

Trong hàm này, bạn sẽ thấy đoạn code kiểm tra input:
```c
// In ra câu đố
plVar21 = FUN_14000d620(&local_198, "Hello kind traveler!... Could you remind me what year it is?...");

// Nhập input vào local_88
FUN_14000da30((basic_istream<> *)pcVar49,(longlong *)&local_88,(ulonglong)bVar16);

// Kiểm tra độ dài input bằng 4
if (local_78 == 4) {
    // So sánh input với giá trị bí mật trong DAT_140010580
    iVar34 = memcmp(pppppcVar32,&DAT_140010580,4);
    if (iVar34 == 0) {
        // NẾU ĐÚNG, CHƯƠNG TRÌNH SẼ TẠO FLAG Ở ĐÂY
        local_1c0 = 0x3367363d5a215235;
        local_1b8 = CONCAT26(local_1b8._6_2_,0x57832603d61);
        local_1d0 = (void *)0x4c5f497b66746370;
        uStack_1c8 = 0x444e31575f335630;
        
        // Vòng lặp giải mã XOR
        lVar30 = 0x10;
        do {
            *(byte *)((longlong)&local_1d0 + lVar30) = *(byte *)((longlong)&local_1d0 + lVar30) ^ 5;
            lVar30 = lVar30 + 1;
        } while (lVar30 != 0x1e);
        // ...
    }
}
```

Chúng ta không cần biết "năm" (input) chính xác là gì, vì logic tạo ra Flag đã nằm ngay trong đoạn code `if (iVar34 == 0)`. Chúng ta chỉ cần tái tạo lại quá trình tính toán các biến này.

### 2. Giải mã Flag
Flag được chia thành 4 phần và được lưu trữ trong bộ nhớ stack liên tiếp nhau. Chúng ta cần xử lý từng biến theo chuẩn **Little Endian** (đảo ngược byte của số Hex).

#### Phần 1: `local_1d0` (Offset 0)
Giá trị: `0x4c5f497b66746370`
Chuyển sang ASCII (Little Endian):
*   Hex: `70 63 74 66 7b 49 5f 4c`
*   ASCII: `p` `c` `t` `f` `{` `I` `_` `L`
*   Chuỗi: **`pctf{I_L`**

#### Phần 2: `uStack_1c8` (Offset 8)
Giá trị: `0x444e31575f335630`
Chuyển sang ASCII (Little Endian):
*   Hex: `30 56 33 5f 57 31 4e 44`
*   ASCII: `0` `V` `3` `_` `W` `1` `N` `D`
*   Chuỗi: **`0V3_W1ND`**

#### Phần 3 & 4: Giải mã XOR
Vòng lặp `do...while` chạy từ offset `0x10` (16) đến `0x1e` (30). Điều này có nghĩa là nó sẽ lấy các byte bắt đầu từ sau Phần 2 và **XOR với 5**.

**Phần 3: `local_1c0` (Offset 16)**
Giá trị: `0x3367363d5a215235`
Bytes (Little Endian): `35 52 21 5a 3d 36 67 33`
Thực hiện XOR 5 từng byte:
*   `0x35 ^ 5 = 0x30` -> **`0`**
*   `0x52 ^ 5 = 0x57` -> **`W`**
*   `0x21 ^ 5 = 0x24` -> **`$`**
*   `0x5a ^ 5 = 0x5f` -> **`_`**
*   `0x3d ^ 5 = 0x38` -> **`8`**
*   `0x36 ^ 5 = 0x33` -> **`3`**
*   `0x67 ^ 5 = 0x62` -> **`b`**
*   `0x33 ^ 5 = 0x36` -> **`6`**
*   Chuỗi: **`0W$_83b6`**

**Phần 4: `local_1b8` (Offset 24)**
Giá trị hằng số trong code là `0x57832603d61` (đã bỏ phần rác `local_1b8._6_2_`).
Bytes (Little Endian): `61 3d 60 32 78 05`
Thực hiện XOR 5 từng byte:
*   `0x61 ^ 5 = 0x64` -> **`d`**
*   `0x3d ^ 5 = 0x38` -> **`8`**
*   `0x60 ^ 5 = 0x65` -> **`e`**
*   `0x32 ^ 5 = 0x37` -> **`7`**
*   `0x78 ^ 5 = 0x7d` -> **`}`**
*   `0x05 ^ 5 = 0x00` -> (Kết thúc chuỗi)
*   Chuỗi: **`d8e7}`**

### 3. Kết quả
Ghép tất cả các chuỗi lại với nhau:
1.  `pctf{I_L`
2.  `0V3_W1ND`
3.  `0W$_83b6`
4.  `d8e7}`

Flag của bài này là:
```
pctf{I_L0V3_W1ND0W$_83b6d8e7}
```