
void FUN_00101020(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}


void FUN_00101110(void)

{
  __cxa_finalize();
  return;
}


/* WARNING: Removing unreachable block (ram,0x00101243) */
/* WARNING: Removing unreachable block (ram,0x0010124f) */

void FUN_00101230(void)

{
  return;
}


/* WARNING: Removing unreachable block (ram,0x00101284) */
/* WARNING: Removing unreachable block (ram,0x00101290) */

void FUN_00101260(void)

{
  return;
}


undefined8 FUN_001012e9(undefined8 param_1)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  
  iVar1 = FUN_001021e1(param_1,0);
  if (iVar1 == 0) {
    uVar2 = FUN_00101b92(2);
  }
  else {
    iVar1 = FUN_001021e1(param_1,1);
    if (iVar1 < 1) {
      uVar2 = FUN_00101b92(1);
    }
    else {
      uVar2 = FUN_00101b92(0);
      uVar3 = FUN_00101b92(0x49);
      FUN_001027fd(uVar3,param_1);
      FUN_001027fd(uVar3,param_1);
      FUN_001027fd(uVar3,param_1);
      FUN_001027fd(uVar3,param_1);
      FUN_001027fd(uVar3,param_1);
      uVar4 = FUN_00101b92(8);
      FUN_001027fd(uVar4,param_1);
      FUN_001027fd(uVar4,param_1);
      FUN_001027fd(uVar4,param_1);
      iVar1 = FUN_001033a9(param_1);
      uVar5 = FUN_00101d21(param_1,iVar1 + 1);
      FUN_00102620(uVar5,1);
      uVar6 = FUN_00101500(uVar5);
      FUN_00102345(uVar2,param_1);
      FUN_00102620(uVar2,4);
      FUN_00102345(uVar2,uVar3);
      FUN_00102345(uVar2,uVar6);
      FUN_00102345(uVar2,uVar4);
      FUN_00101f42(uVar3);
      FUN_00101f42(uVar6);
      FUN_00101f42(uVar4);
      FUN_00101f42(uVar5);
    }
  }
  return uVar2;
}


undefined8 FUN_00101500(undefined8 param_1)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  
  iVar1 = FUN_001021e1(param_1,1);
  if (iVar1 < 1) {
    uVar2 = FUN_00101b92(1);
  }
  else {
    uVar2 = FUN_00101b92(0);
    iVar1 = FUN_001033a9(param_1);
    uVar3 = FUN_00101d21(param_1,iVar1 + 1);
    FUN_00102620(uVar3,1);
    uVar4 = FUN_001012e9(uVar3);
    iVar1 = FUN_001033a9(param_1);
    uVar5 = FUN_00101d21(param_1,iVar1 + 1);
    FUN_00102620(uVar5,2);
    uVar6 = FUN_001012e9(uVar5);
    FUN_00102abc(uVar6,3);
    iVar1 = FUN_001033a9(param_1);
    uVar7 = FUN_00101d21(param_1,iVar1 + 1);
    FUN_00102620(uVar7,3);
    uVar8 = FUN_001012e9(uVar7);
    FUN_00102abc(uVar8,5);
    uVar9 = FUN_00101b92(3);
    FUN_001027fd(uVar9,param_1);
    FUN_001027fd(uVar9,param_1);
    FUN_001027fd(uVar9,param_1);
    FUN_001027fd(uVar9,param_1);
    FUN_00102345(uVar2,uVar4);
    FUN_00102345(uVar2,uVar6);
    FUN_0010258d(uVar2,uVar8);
    FUN_00102345(uVar2,uVar9);
    FUN_00101f42(uVar6);
    FUN_00101f42(uVar8);
    FUN_00101f42(uVar9);
    FUN_00101f42(uVar3);
    FUN_00101f42(uVar5);
    FUN_00101f42(uVar7);
  }
  return uVar2;
}


undefined8 FUN_0010175e(undefined8 param_1,undefined8 param_2)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = FUN_001033a9(param_1);
  uVar2 = FUN_00101d21(param_1,iVar1 + 1);
  while( true ) {
    iVar1 = FUN_00102126(uVar2,param_2);
    if (iVar1 < 0) {
      return uVar2;
    }
    iVar1 = FUN_00102126(uVar2,param_2);
    if (iVar1 == 0) break;
    FUN_0010258d(uVar2,param_2);
  }
  FUN_00101f42(uVar2);
  uVar2 = FUN_00101b92(0);
  return uVar2;
}


undefined8 FUN_001017f4(undefined8 param_1,undefined8 param_2)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  
  iVar1 = FUN_001033a9(param_1);
  uVar2 = FUN_00101d21(param_1,iVar1 + 1);
  uVar3 = FUN_0010175e(uVar2,param_2);
  FUN_00102345(uVar3,param_2);
  FUN_0010175e(uVar3,param_2);
  FUN_00101f42(uVar2);
  return uVar3;
}


undefined8 FUN_00101878(undefined8 param_1)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  
  uVar2 = FUN_001012e9(param_1);
  iVar1 = FUN_001021e1(param_1,100);
  if (0 < iVar1) {
    uVar3 = FUN_00101dec(PTR_s_12871709638832864416674237492708_00106010);
    uVar4 = FUN_00101dec(PTR_s_80512964945028911137409821534504_00106018);
    uVar5 = FUN_001017f4(uVar2,uVar3);
    FUN_00102345(uVar5,uVar4);
    FUN_00101f42(uVar3);
    FUN_00101f42(uVar4);
    FUN_00101f42(uVar2);
    uVar2 = uVar5;
  }
  return uVar2;
}


undefined8 FUN_0010192d(int param_1,undefined8 *param_2)

{
  int iVar1;
  undefined8 uVar2;
  long lVar3;
  void *__ptr;
  
  if (param_1 == 2) {
    lVar3 = FUN_00101dec(param_2[1]);
    if (lVar3 == 0) {
      fprintf(stderr,"Invalid number: %s\n",param_2[1]);
      uVar2 = 1;
    }
    else {
      iVar1 = FUN_001021e1(lVar3,0);
      if (iVar1 < 0) {
        fprintf(stderr,"Invalid number: %s\n",param_2[1]);
        FUN_00101f42(lVar3);
        uVar2 = 1;
      }
      else {
        puts("allocating memory... lots... of... memory...");
        sleep(3);
        puts("warming up the CPU...");
        sleep(3);
        puts("increasing fan speed...");
        sleep(3);
        puts("calculating...");
        uVar2 = FUN_00101878(lVar3);
        __ptr = (void *)FUN_001034cc(uVar2);
        printf("flag: %s\n",__ptr);
        FUN_00101f42(uVar2);
        FUN_00101f42(lVar3);
        free(__ptr);
        uVar2 = 0;
      }
    }
  }
  else {
    fprintf(stderr,"Usage: %s <number>\n",*param_2);
    uVar2 = 1;
  }
  return uVar2;
}


undefined8 FUN_00101ada(long param_1)

{
  undefined8 uVar1;
  
  if ((param_1 < -0x80000000) || (0x7fffffff < param_1)) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}


bool FUN_00101b0b(int param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  
  *param_3 = (int)((long)param_2 + (long)param_1);
  iVar1 = FUN_00101ada((long)param_2 + (long)param_1);
  return iVar1 == 0;
}


bool FUN_00101b4e(int param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  
  *param_3 = (int)((long)param_2 * (long)param_1);
  iVar1 = FUN_00101ada((long)param_2 * (long)param_1);
  return iVar1 == 0;
}


/* WARNING: Removing unreachable block (ram,0x00101bfe) */

long * FUN_00101b92(uint param_1)

{
  long *__ptr;
  void *pvVar1;
  double dVar2;
  uint local_20;
  int local_1c;
  char *local_18;
  
  __ptr = (long *)malloc(0x18);
  if (__ptr == (long *)0x0) {
    __ptr = (long *)0x0;
  }
  else {
    if ((int)param_1 < 0) {
      *(undefined1 *)(__ptr + 2) = 1;
      local_20 = -param_1;
    }
    else {
      *(undefined1 *)(__ptr + 2) = 0;
      local_20 = param_1;
    }
    dVar2 = log10((double)local_20);
    dVar2 = floor(dVar2);
    *(int *)(__ptr + 1) = (int)(long)(dVar2 + 1.0);
    if ((int)__ptr[1] == 0) {
      *(undefined4 *)(__ptr + 1) = 1;
    }
    *(int *)((long)__ptr + 0xc) = (int)__ptr[1];
    pvVar1 = malloc((ulong)*(uint *)((long)__ptr + 0xc));
    *__ptr = (long)pvVar1;
    if (*__ptr == 0) {
      free(__ptr);
      __ptr = (long *)0x0;
    }
    else {
      local_1c = (int)__ptr[1];
      local_18 = (char *)*__ptr;
      while (local_1c != 0) {
        *local_18 = (char)local_20 + (char)(local_20 / 10) * -10;
        local_20 = local_20 / 10;
        local_1c = local_1c + -1;
        local_18 = local_18 + 1;
      }
    }
  }
  return __ptr;
}


long * FUN_00101d21(undefined8 *param_1,uint param_2)

{
  long *__ptr;
  void *pvVar1;
  uint local_24;
  
  local_24 = param_2;
  if (param_2 < *(uint *)(param_1 + 1)) {
    local_24 = *(uint *)(param_1 + 1);
  }
  __ptr = (long *)malloc(0x18);
  if (__ptr == (long *)0x0) {
    __ptr = (long *)0x0;
  }
  else {
    pvVar1 = malloc((ulong)local_24);
    *__ptr = (long)pvVar1;
    if (*__ptr == 0) {
      free(__ptr);
      __ptr = (long *)0x0;
    }
    else {
      *(uint *)((long)__ptr + 0xc) = local_24;
      *(undefined1 *)(__ptr + 2) = *(undefined1 *)(param_1 + 2);
      *(undefined4 *)(__ptr + 1) = *(undefined4 *)(param_1 + 1);
      memmove((void *)*__ptr,(void *)*param_1,(ulong)*(uint *)(param_1 + 1));
    }
  }
  return __ptr;
}


long * FUN_00101dec(byte *param_1)

{
  byte bVar1;
  size_t sVar2;
  long *__ptr;
  void *pvVar3;
  int *piVar4;
  byte *local_30;
  byte *local_20;
  char *local_18;
  
  bVar1 = *param_1;
  local_30 = param_1;
  if (bVar1 == 0x2d) {
    local_30 = param_1 + 1;
  }
  for (; (*local_30 == 0x30 && (*local_30 != 0)); local_30 = local_30 + 1) {
  }
  sVar2 = strlen((char *)local_30);
  __ptr = (long *)malloc(0x18);
  if (__ptr == (long *)0x0) {
    __ptr = (long *)0x0;
  }
  else {
    *(bool *)(__ptr + 2) = bVar1 == 0x2d;
    *(int *)((long)__ptr + 0xc) = (int)sVar2;
    pvVar3 = malloc(sVar2 & 0xffffffff);
    *__ptr = (long)pvVar3;
    if (*__ptr == 0) {
      free(__ptr);
      __ptr = (long *)0x0;
    }
    else {
      local_20 = local_30 + ((sVar2 & 0xffffffff) - 1);
      local_18 = (char *)*__ptr;
      while (local_30 <= local_20) {
        bVar1 = *local_20;
        if ((bVar1 < 0x30) || (0x39 < bVar1)) {
          FUN_00101f42(__ptr);
          piVar4 = __errno_location();
          *piVar4 = 0x16;
          return (long *)0x0;
        }
        *local_18 = bVar1 - 0x30;
        local_20 = local_20 + -1;
        local_18 = local_18 + 1;
      }
      *(int *)(__ptr + 1) = (int)local_18 - (int)*__ptr;
    }
  }
  return __ptr;
}


void FUN_00101f42(undefined8 *param_1)

{
  if (param_1 != (undefined8 *)0x0) {
    free((void *)*param_1);
    free(param_1);
  }
  return;
}


bool FUN_00101f77(undefined8 *param_1,undefined8 *param_2)

{
  char cVar1;
  
  cVar1 = FUN_0010352a(param_1,*(undefined4 *)(param_2 + 1));
  if (cVar1 != '\0') {
    memmove((void *)*param_1,(void *)*param_2,(ulong)*(uint *)(param_2 + 1));
    *(undefined1 *)(param_1 + 2) = *(undefined1 *)(param_2 + 2);
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(param_2 + 1);
  }
  return cVar1 != '\0';
}


/* WARNING: Removing unreachable block (ram,0x0010202a) */

undefined8 FUN_00101ff1(undefined8 *param_1,uint param_2)

{
  char cVar1;
  undefined8 uVar2;
  double dVar3;
  uint local_18;
  int local_14;
  char *local_10;
  
  *(undefined1 *)(param_1 + 2) = 0;
  dVar3 = log10((double)param_2);
  dVar3 = floor(dVar3);
  *(int *)(param_1 + 1) = (int)(long)(dVar3 + 1.0);
  if (*(int *)(param_1 + 1) == 0) {
    *(undefined4 *)(param_1 + 1) = 1;
  }
  cVar1 = FUN_0010352a(param_1,*(undefined4 *)(param_1 + 1));
  if (cVar1 == '\0') {
    uVar2 = 0;
  }
  else {
    local_18 = param_2;
    local_14 = *(int *)(param_1 + 1);
    local_10 = (char *)*param_1;
    while (local_14 != 0) {
      *local_10 = (char)local_18 + (char)(local_18 / 10) * -10;
      local_18 = local_18 / 10;
      local_14 = local_14 + -1;
      local_10 = local_10 + 1;
    }
    uVar2 = 1;
  }
  return uVar2;
}


undefined8 FUN_00102126(undefined8 *param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  
  if ((((*(int *)(param_1 + 1) != 0) || (*(char *)*param_1 != '\0')) || (*(int *)(param_2 + 1) != 0)
      ) || (*(char *)*param_2 != '\0')) {
    if ((*(char *)(param_1 + 2) != '\0') && (*(char *)(param_2 + 2) == '\0')) {
      return 0xffffffff;
    }
    if ((*(char *)(param_1 + 2) == '\0') && (*(char *)(param_2 + 2) != '\0')) {
      return 1;
    }
  }
  if (*(char *)(param_1 + 2) == '\0') {
    uVar1 = FUN_0010226d(param_1,param_2);
  }
  else {
    uVar1 = FUN_0010226d(param_2,param_1);
  }
  return uVar1;
}


undefined8 FUN_001021e1(long param_1,int param_2)

{
  char cVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  cVar1 = FUN_00103188(param_1,&local_14);
  if (cVar1 == '\0') {
    if (*(char *)(param_1 + 0x10) == '\0') {
      uVar2 = 1;
    }
    else {
      uVar2 = 0xffffffff;
    }
  }
  else if (param_2 == local_14) {
    uVar2 = 0;
  }
  else if (local_14 < param_2) {
    uVar2 = 0xffffffff;
  }
  else {
    uVar2 = 1;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}


undefined8 FUN_0010226d(long *param_1,long *param_2)

{
  char cVar1;
  char cVar2;
  undefined8 uVar3;
  int local_1c;
  char *local_18;
  char *local_10;
  
  if (*(uint *)(param_2 + 1) < *(uint *)(param_1 + 1)) {
    uVar3 = 1;
  }
  else if (*(uint *)(param_1 + 1) < *(uint *)(param_2 + 1)) {
    uVar3 = 0xffffffff;
  }
  else {
    local_1c = (int)param_1[1];
    local_18 = (char *)(*param_1 + (ulong)(local_1c - 1));
    local_10 = (char *)(*param_2 + (ulong)(local_1c - 1));
    do {
      if (local_1c == 0) {
        return 0;
      }
      cVar1 = *local_18;
      cVar2 = *local_10;
      if (cVar2 < cVar1) {
        return 1;
      }
      local_1c = local_1c + -1;
      local_18 = local_18 + -1;
      local_10 = local_10 + -1;
    } while (cVar2 <= cVar1);
    uVar3 = 0xffffffff;
  }
  return uVar3;
}


undefined8 FUN_00102345(long param_1,long param_2)

{
  undefined1 uVar1;
  char cVar2;
  int iVar3;
  
  if (*(char *)(param_1 + 0x10) == *(char *)(param_2 + 0x10)) {
    cVar2 = FUN_00102445(param_1,param_2);
    if (cVar2 == '\0') {
      return 0;
    }
  }
  else {
    iVar3 = FUN_0010226d(param_1,param_2);
    if (iVar3 < 1) {
      uVar1 = *(undefined1 *)(param_2 + 0x10);
    }
    else {
      uVar1 = *(undefined1 *)(param_1 + 0x10);
    }
    cVar2 = FUN_00102677(param_1,param_2);
    if (cVar2 == '\0') {
      return 0;
    }
    *(undefined1 *)(param_1 + 0x10) = uVar1;
  }
  return 1;
}


undefined1 FUN_001023ee(undefined8 param_1,undefined4 param_2)

{
  undefined1 uVar1;
  long lVar2;
  
  lVar2 = FUN_00101b92(param_2);
  if (lVar2 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = FUN_00102345(param_1,lVar2);
    FUN_00101f42(lVar2);
  }
  return uVar1;
}


undefined8 FUN_00102445(long *param_1,long *param_2)

{
  char cVar1;
  uint uVar2;
  undefined8 uVar3;
  uint local_1c;
  uint local_18;
  
  uVar2 = *(uint *)(param_1 + 1);
  if (*(uint *)(param_1 + 1) <= *(uint *)(param_2 + 1)) {
    uVar2 = *(uint *)(param_2 + 1);
  }
  cVar1 = FUN_0010352a(param_1,uVar2 + 1);
  if (cVar1 == '\0') {
    uVar3 = 0;
  }
  else {
    local_1c = 0;
    for (local_18 = 0; (local_1c < *(uint *)(param_2 + 1) || (local_18 != 0));
        local_18 = (uint)(9 < local_18)) {
      if (*(uint *)(param_1 + 1) == local_1c) {
        *(int *)(param_1 + 1) = (int)param_1[1] + 1;
        *(undefined1 *)((long)(int)local_1c + *param_1) = 0;
      }
      if (local_1c < *(uint *)(param_2 + 1)) {
        uVar2 = (uint)*(byte *)((long)(int)local_1c + *param_2);
      }
      else {
        uVar2 = 0;
      }
      local_18 = local_18 + *(byte *)((long)(int)local_1c + *param_1) + uVar2;
      *(char *)((long)(int)local_1c + *param_1) = (char)local_18 + (char)(local_18 / 10) * -10;
      local_1c = local_1c + 1;
    }
    uVar3 = 1;
  }
  return uVar3;
}


undefined8 FUN_0010258d(long param_1,long param_2)

{
  char cVar1;
  byte extraout_var;
  
  FUN_00102126(param_1,param_2);
  if (*(char *)(param_1 + 0x10) == *(char *)(param_2 + 0x10)) {
    cVar1 = FUN_00102677(param_1,param_2);
    if (cVar1 == '\0') {
      return 0;
    }
  }
  else {
    cVar1 = FUN_00102445(param_1,param_2);
    if (cVar1 == '\0') {
      return 0;
    }
  }
  *(byte *)(param_1 + 0x10) = extraout_var >> 7;
  return 1;
}


undefined1 FUN_00102620(undefined8 param_1,undefined4 param_2)

{
  undefined1 uVar1;
  long lVar2;
  
  lVar2 = FUN_00101b92(param_2);
  if (lVar2 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = FUN_0010258d(param_1,lVar2);
    FUN_00101f42(lVar2);
  }
  return uVar1;
}


undefined8 FUN_00102677(long *param_1,long *param_2)

{
  char cVar1;
  int iVar2;
  undefined8 uVar3;
  uint uVar4;
  uint local_30;
  uint local_2c;
  uint local_28;
  int local_24;
  int local_20;
  long local_18;
  long local_10;
  
  uVar4 = *(uint *)(param_1 + 1);
  if (*(uint *)(param_1 + 1) <= *(uint *)(param_2 + 1)) {
    uVar4 = *(uint *)(param_2 + 1);
  }
  cVar1 = FUN_0010352a(param_1,uVar4 + 1);
  if (cVar1 == '\0') {
    uVar3 = 0;
  }
  else {
    iVar2 = FUN_0010226d(param_1,param_2);
    if (iVar2 < 1) {
      local_18 = *param_2;
      local_2c = *(uint *)(param_2 + 1);
      local_10 = *param_1;
      local_30 = *(uint *)(param_1 + 1);
    }
    else {
      local_18 = *param_1;
      local_2c = *(uint *)(param_1 + 1);
      local_10 = *param_2;
      local_30 = *(uint *)(param_2 + 1);
    }
    local_24 = 0;
    *(undefined4 *)(param_1 + 1) = 1;
    for (local_28 = 0; local_28 < local_2c; local_28 = local_28 + 1) {
      if (local_28 < local_30) {
        uVar4 = (uint)*(byte *)(local_18 + (int)local_28) -
                (uint)*(byte *)(local_10 + (int)local_28);
      }
      else {
        uVar4 = (uint)*(byte *)(local_18 + (int)local_28);
      }
      local_20 = local_24 + uVar4;
      if (local_20 < 0) {
        local_24 = -1;
        local_20 = local_20 + 10;
      }
      else {
        local_24 = 0;
      }
      *(char *)((long)(int)local_28 + *param_1) = (char)local_20;
      if (local_20 != 0) {
        *(uint *)(param_1 + 1) = local_28 + 1;
      }
    }
    uVar3 = 1;
  }
  return uVar3;
}


undefined1 FUN_001027fd(long *param_1,long *param_2)

{
  char cVar1;
  undefined1 uVar2;
  long *plVar3;
  long *plVar4;
  uint local_2c;
  uint local_28;
  int local_24;
  int local_20;
  
  plVar3 = (long *)FUN_00101b92(0);
  if (plVar3 == (long *)0x0) {
    uVar2 = 0;
  }
  else {
    plVar4 = (long *)FUN_00101b92(0);
    if (plVar4 == (long *)0x0) {
      FUN_00101f42(plVar3);
      uVar2 = 0;
    }
    else {
      cVar1 = FUN_0010352a(plVar4,(int)param_2[1] + (int)param_1[1] + 1);
      if (cVar1 == '\0') {
        FUN_00101f42(plVar3);
        FUN_00101f42(plVar4);
        uVar2 = 0;
      }
      else {
        local_24 = 0;
        for (local_2c = 0; local_2c < *(uint *)(param_2 + 1); local_2c = local_2c + 1) {
          if (0 < (int)local_2c) {
            *(uint *)(plVar4 + 1) = local_2c;
            *(undefined1 *)(*plVar4 + (long)(int)local_2c + -1) = 0;
          }
          local_28 = 0;
          while ((local_28 < *(uint *)(param_1 + 1) || (0 < local_24))) {
            if (local_2c + local_28 == (int)plVar4[1]) {
              *(int *)(plVar4 + 1) = (int)plVar4[1] + 1;
            }
            if (local_28 < *(uint *)(param_1 + 1)) {
              local_20 = local_24 +
                         (uint)*(byte *)((long)(int)local_28 + *param_1) *
                         (uint)*(byte *)((long)(int)local_2c + *param_2);
            }
            else {
              local_20 = local_24;
            }
            *(char *)((long)(int)(local_28 + local_2c) + *plVar4) =
                 (char)local_20 + (char)(local_20 / 10) * -10;
            local_28 = local_28 + 1;
            local_24 = local_20 / 10;
          }
          cVar1 = FUN_00102345(plVar3,plVar4);
          if (cVar1 == '\0') {
            FUN_00101f42(plVar3);
            FUN_00101f42(plVar4);
            return 0;
          }
        }
        *(bool *)(plVar3 + 2) = (char)param_1[2] != (char)param_2[2];
        while ((1 < *(uint *)(plVar3 + 1) &&
               (*(char *)((ulong)((int)plVar3[1] - 1) + *plVar3) == '\0'))) {
          *(int *)(plVar3 + 1) = (int)plVar3[1] + -1;
        }
        uVar2 = FUN_00101f77(param_1,plVar3);
        FUN_00101f42(plVar3);
        FUN_00101f42(plVar4);
      }
    }
  }
  return uVar2;
}


undefined1 FUN_00102abc(undefined8 param_1,undefined4 param_2)

{
  undefined1 uVar1;
  long lVar2;
  
  lVar2 = FUN_00101b92(param_2);
  if (lVar2 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = FUN_001027fd(param_1,lVar2);
    FUN_00101f42(lVar2);
  }
  return uVar1;
}


undefined4 FUN_00102b13(undefined8 *param_1,long param_2,long param_3,long param_4)

{
  undefined1 *puVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  long in_FS_OFFSET;
  undefined4 local_dc;
  int local_d8;
  int local_d4;
  long local_d0;
  long local_c8;
  long local_c0;
  long local_b8;
  long local_b0;
  long local_a8;
  long local_a0;
  long local_98;
  long local_90;
  long local_88;
  long local_80;
  undefined1 *local_78;
  long alStack_68 [4];
  long local_48;
  long local_40;
  long local_38;
  long local_30;
  long local_28;
  long local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_dc = 0;
  local_d0 = 0;
  local_c8 = 0;
  local_c0 = 0;
  local_b8 = 0;
  local_b0 = 0;
  local_a8 = 0;
  local_a0 = 0;
  local_98 = 0;
  local_90 = 0;
  local_88 = 0;
  local_80 = 0;
  iVar3 = FUN_001021e1(param_2,0);
  if (iVar3 == 0) {
    piVar4 = __errno_location();
    *piVar4 = 0x22;
  }
  else {
    local_d0 = FUN_00101d21(param_2,*(int *)(param_2 + 8) + 1);
    if (((((((local_d0 != 0) && (cVar2 = FUN_00102abc(local_d0,2), cVar2 != '\0')) &&
           (local_c8 = FUN_00101d21(param_2,*(int *)(param_2 + 8) + 1), local_c8 != 0)) &&
          ((cVar2 = FUN_00102abc(local_c8,3), cVar2 != '\0' &&
           (local_c0 = FUN_00101d21(param_2,*(int *)(param_2 + 8) + 1), local_c0 != 0)))) &&
         ((cVar2 = FUN_00102abc(local_c0,4), cVar2 != '\0' &&
          ((local_b8 = FUN_00101d21(param_2,*(int *)(param_2 + 8) + 1), local_b8 != 0 &&
           (cVar2 = FUN_00102abc(local_b8,5), cVar2 != '\0')))))) &&
        (local_b0 = FUN_00101d21(param_2,*(int *)(param_2 + 8) + 1), local_b0 != 0)) &&
       ((((cVar2 = FUN_00102abc(local_b0,6), cVar2 != '\0' &&
          (local_a8 = FUN_00101d21(param_2,*(int *)(param_2 + 8) + 1), local_a8 != 0)) &&
         (cVar2 = FUN_00102abc(local_a8,7), cVar2 != '\0')) &&
        (((local_a0 = FUN_00101d21(param_2,*(int *)(param_2 + 8) + 1), local_a0 != 0 &&
          (cVar2 = FUN_00102abc(local_a0,8), cVar2 != '\0')) &&
         ((local_98 = FUN_00101d21(param_2,*(int *)(param_2 + 8) + 1), local_98 != 0 &&
          (cVar2 = FUN_00102abc(local_98,9), cVar2 != '\0')))))))) {
      local_90 = FUN_00101b92(10);
      local_88 = FUN_00101b92(0);
      local_80 = FUN_00101b92(0);
      if (((local_90 != 0) && (local_88 != 0)) && (local_80 != 0)) {
        puVar1 = (undefined1 *)*param_1;
        alStack_68[1] = param_2;
        alStack_68[2] = local_d0;
        alStack_68[3] = local_c8;
        local_48 = local_c0;
        local_40 = local_b8;
        local_38 = local_b0;
        local_30 = local_a8;
        local_28 = local_a0;
        local_20 = local_98;
        for (local_78 = puVar1 + (*(int *)(param_1 + 1) - 1); puVar1 <= local_78;
            local_78 = local_78 + -1) {
          cVar2 = FUN_001027fd(local_80,local_90);
          if ((cVar2 == '\0') || (cVar2 = FUN_001023ee(local_80,*local_78), cVar2 == '\0'))
          goto LAB_001030cd;
          local_d8 = 0;
          for (local_d4 = 9; 0 < local_d4; local_d4 = local_d4 + -1) {
            iVar3 = FUN_00102126(local_80,alStack_68[local_d4]);
            if (-1 < iVar3) {
              cVar2 = FUN_0010258d(local_80,alStack_68[local_d4]);
              if (cVar2 == '\0') goto LAB_001030cd;
              local_d8 = local_d4;
              break;
            }
          }
          cVar2 = FUN_001027fd(local_88,local_90);
          if ((cVar2 == '\0') || (cVar2 = FUN_001023ee(local_88,local_d8), cVar2 == '\0'))
          goto LAB_001030cd;
        }
        if (((param_3 == 0) || (cVar2 = FUN_00101f77(param_3,local_88), cVar2 != '\0')) &&
           ((param_4 == 0 || (cVar2 = FUN_00101f77(param_4,local_80), cVar2 != '\0')))) {
          local_dc = 1;
        }
      }
    }
  }
LAB_001030cd:
  FUN_00101f42(local_d0);
  FUN_00101f42(local_c8);
  FUN_00101f42(local_c0);
  FUN_00101f42(local_b8);
  FUN_00101f42(local_b0);
  FUN_00101f42(local_a8);
  FUN_00101f42(local_a0);
  FUN_00101f42(local_98);
  FUN_00101f42(local_90);
  FUN_00101f42(local_80);
  FUN_00101f42(local_88);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return local_dc;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


undefined8 FUN_00103188(undefined8 *param_1,uint *param_2)

{
  int iVar1;
  byte *pbVar2;
  char cVar3;
  int *piVar4;
  undefined8 uVar5;
  long in_FS_OFFSET;
  undefined4 local_24;
  uint local_20;
  int local_1c;
  byte *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  *param_2 = 0;
  local_24 = 1;
  local_1c = *(int *)(param_1 + 1);
  pbVar2 = (byte *)*param_1;
  while ((local_1c != 0 && (pbVar2[local_1c - 1] == 0))) {
    local_1c = local_1c + -1;
  }
  local_18 = pbVar2;
  if (local_1c != 0) {
    local_18 = pbVar2 + 1;
    *param_2 = (uint)*pbVar2;
    local_1c = local_1c + -1;
  }
  do {
    iVar1 = local_1c + -1;
    if (local_1c == 0) {
      local_1c = iVar1;
      if (*(char *)(param_1 + 2) != '\0') {
        cVar3 = FUN_00101b4e(*param_2,0xffffffff,param_2);
        if (cVar3 != '\x01') {
          piVar4 = __errno_location();
          *piVar4 = 0x22;
          uVar5 = 0;
          goto LAB_001032e4;
        }
      }
      uVar5 = 1;
      goto LAB_001032e4;
    }
    local_20 = (uint)*local_18;
    local_1c = iVar1;
    local_18 = local_18 + 1;
    cVar3 = FUN_00101b4e(local_24,10,&local_24);
    if (cVar3 != '\x01') break;
    cVar3 = FUN_00101b4e(local_20,local_24,&local_20);
    if (cVar3 != '\x01') break;
    cVar3 = FUN_00101b0b(*param_2,local_20,param_2);
  } while (cVar3 == '\x01');
  piVar4 = __errno_location();
  *piVar4 = 0x22;
  uVar5 = 0;
LAB_001032e4:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar5;
}


void FUN_001032fa(undefined8 param_1)

{
  FUN_00103323(stdout,param_1);
  return;
}


void FUN_00103323(FILE *param_1,undefined8 *param_2)

{
  byte *pbVar1;
  byte *local_18;
  
  pbVar1 = (byte *)*param_2;
  local_18 = pbVar1 + (*(int *)(param_2 + 1) - 1);
  if (*(char *)(param_2 + 2) != '\0') {
    fputc(0x2d,param_1);
  }
  while (pbVar1 <= local_18) {
    fputc(*local_18 + 0x30,param_1);
    local_18 = local_18 + -1;
  }
  return;
}


int FUN_001033a9(long param_1)

{
  undefined4 local_c;
  
  local_c = *(int *)(param_1 + 8);
  if (*(char *)(param_1 + 0x10) != '\0') {
    local_c = local_c + 1;
  }
  return local_c;
}


bool FUN_001033d4(undefined8 *param_1,char *param_2,int param_3)

{
  char *pcVar1;
  int *piVar2;
  int local_2c;
  char *local_28;
  char *local_18;
  
  pcVar1 = (char *)*param_1;
  local_18 = pcVar1 + (*(int *)(param_1 + 1) - 1);
  local_2c = param_3;
  local_28 = param_2;
  if (*(char *)(param_1 + 2) != '\0') {
    if (param_3 == 0) {
      piVar2 = __errno_location();
      *piVar2 = 0x22;
      return false;
    }
    *param_2 = '-';
    local_2c = param_3 + -1;
    local_28 = param_2 + 1;
  }
  while( true ) {
    if (local_18 < pcVar1) {
      if (local_2c != 0) {
        *local_28 = '\0';
      }
      else {
        piVar2 = __errno_location();
        *piVar2 = 0x22;
      }
      return local_2c != 0;
    }
    if (local_2c == 0) break;
    *local_28 = *local_18 + '0';
    local_2c = local_2c + -1;
    local_28 = local_28 + 1;
    local_18 = local_18 + -1;
  }
  piVar2 = __errno_location();
  *piVar2 = 0x22;
  return false;
}


void * FUN_001034cc(undefined8 param_1)

{
  int iVar1;
  void *pvVar2;
  
  iVar1 = FUN_001033a9(param_1);
  pvVar2 = malloc((ulong)(iVar1 + 1U));
  if (pvVar2 == (void *)0x0) {
    pvVar2 = (void *)0x0;
  }
  else {
    FUN_001033d4(param_1,pvVar2,iVar1 + 1U);
  }
  return pvVar2;
}


undefined8 FUN_0010352a(undefined8 *param_1,uint param_2)

{
  void *__src;
  void *__dest;
  
  if (*(uint *)((long)param_1 + 0xc) < param_2) {
    __dest = malloc((ulong)param_2);
    if (__dest == (void *)0x0) {
      return 0;
    }
    __src = (void *)*param_1;
    memcpy(__dest,__src,(ulong)*(uint *)(param_1 + 1));
    *param_1 = __dest;
    *(uint *)((long)param_1 + 0xc) = param_2;
    free(__src);
  }
  return 1;
}

