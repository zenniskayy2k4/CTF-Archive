
//==================================================
// Function: _DT_INIT at 00101000
//==================================================

void _DT_INIT(void)

{
  if (PTR___gmon_start___00103fd0 != (undefined *)0x0) {
    (*(code *)PTR___gmon_start___00103fd0)();
  }
  return;
}



//==================================================
// Function: FUN_00101020 at 00101020
//==================================================

void FUN_00101020(void)

{
  (*(code *)PTR_00103ff8)();
  return;
}



//==================================================
// Function: entry at 00101090
//==================================================

void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00103fc0)
            (FUN_00101230,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



//==================================================
// Function: FUN_001010c0 at 001010c0
//==================================================

/* WARNING: Removing unreachable block (ram,0x001010d3) */
/* WARNING: Removing unreachable block (ram,0x001010df) */

void FUN_001010c0(void)

{
  return;
}



//==================================================
// Function: FUN_001010f0 at 001010f0
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101114) */
/* WARNING: Removing unreachable block (ram,0x00101120) */

void FUN_001010f0(void)

{
  return;
}



//==================================================
// Function: _FINI_0 at 00101130
//==================================================

void _FINI_0(void)

{
  if (DAT_00104929 == '\0') {
    if (PTR___cxa_finalize_00103fe0 != (undefined *)0x0) {
      __cxa_finalize(PTR_LOOP_00104038);
    }
    FUN_001010c0();
    DAT_00104929 = 1;
    return;
  }
  return;
}



//==================================================
// Function: FUN_00101180 at 00101180
//==================================================

void FUN_00101180(void)

{
  FUN_00101570(&DAT_0010492a,&DAT_0010405e);
  printf(&DAT_0010492a);
  FUN_00101610(&DAT_001049c3,&DAT_00104123);
  printf(&DAT_001049c3);
  FUN_001016a0(&DAT_001049ff,&DAT_00104189);
  printf(&DAT_001049ff);
  FUN_00101720(&DAT_00104a38,&DAT_001041eb);
  printf(&DAT_00104a38);
  FUN_001017a0(&DAT_00104a70,&DAT_00104254);
  printf(&DAT_00104a70);
  return;
}



//==================================================
// Function: FUN_00101230 at 00101230
//==================================================

undefined4 FUN_00101230(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  time_t tVar7;
  undefined4 uVar8;
  char *__format;
  uint local_44;
  uint local_40;
  uint local_3c;
  uint local_38;
  uint local_34;
  
  FUN_00101180();
  tVar7 = time((time_t *)0x0);
  srand((uint)tVar7);
  iVar1 = rand();
  iVar2 = rand();
  iVar3 = rand();
  iVar4 = rand();
  iVar5 = rand();
  FUN_00101830(&DAT_00104b0a,&DAT_0010431c);
  printf(&DAT_00104b0a);
  FUN_001018b0(&DAT_00104b43,&DAT_00104381);
  printf(&DAT_00104b43);
  FUN_00101930(&DAT_00104b85,&DAT_001043f2);
  printf(&DAT_00104b85);
  FUN_001019d0(&DAT_00104bc7,&DAT_00104466);
  printf(&DAT_00104bc7);
  FUN_00101a50(&DAT_00104bfa,&DAT_001044c3);
  printf(&DAT_00104bfa);
  FUN_00101ab0(&DAT_00104c24,&DAT_00104512);
  iVar6 = __isoc99_scanf(&DAT_00104c24,&local_34,&local_38,&local_3c,&local_40,&local_44);
  if (iVar6 == 5) {
    if ((((local_34 == iVar1 % 1000) && (local_38 == iVar2 % 1000)) && (local_3c == iVar3 % 1000))
       && ((local_40 == iVar4 % 1000 && (local_44 == iVar5 % 1000)))) {
      FUN_00101ba0(&DAT_00104c55,&DAT_001045a0);
      uVar8 = 0;
      printf(&DAT_00104c55);
      FUN_00101c30(&DAT_00104ce1,&DAT_00104658);
      printf(&DAT_00104ce1);
      FUN_00101cb0(&DAT_00104d10,&DAT_001046ba);
      printf(&DAT_00104d10);
      __format = &DAT_00104d9c;
      FUN_00101d30(&DAT_00104d9c,&DAT_0010476d);
    }
    else {
      FUN_00101db0(&DAT_00104dd4,&DAT_001047da);
      uVar8 = 0;
      printf(&DAT_00104dd4,(ulong)(uint)(iVar1 % 1000),(ulong)(uint)(iVar2 % 1000),
             (ulong)(uint)(iVar3 % 1000),(ulong)(uint)(iVar4 % 1000),(ulong)(uint)(iVar5 % 1000));
      FUN_00101e40(&DAT_00104e07,&DAT_00104840);
      printf(&DAT_00104e07);
      FUN_00101ea0(&DAT_00104e24,&DAT_00104893);
      printf(&DAT_00104e24);
      __format = &DAT_00104e5b;
      FUN_00101f20(&DAT_00104e5b,&DAT_001048ed);
    }
  }
  else {
    __format = &DAT_00104c34;
    FUN_00101b10(&DAT_00104c34,&DAT_00104553);
    uVar8 = 1;
  }
  printf(__format);
  return uVar8;
}



//==================================================
// Function: FUN_00101570 at 00101570
//==================================================

void FUN_00101570(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_001049c2 == '\0') {
    lVar4 = 0x15;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x15);
      if (((int)(uVar2 % 0x15) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x15 + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0xad);
    DAT_001049c2 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101610 at 00101610
//==================================================

void FUN_00101610(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_001049fe == '\0') {
    lVar4 = 0x17;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x17);
      if (((int)(uVar2 % 0x17) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x17 + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x52);
    DAT_001049fe = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_001016a0 at 001016a0
//==================================================

void FUN_001016a0(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104a37 == '\0') {
    lVar4 = 0x13;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x13);
      if (((int)(uVar2 % 0x13) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x13 + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x4b);
    DAT_00104a37 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101720 at 00101720
//==================================================

void FUN_00101720(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104a6f == '\0') {
    lVar4 = 0x1a;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x1a);
      if (((int)(uVar2 % 0x1a) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x1a + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x51);
    DAT_00104a6f = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_001017a0 at 001017a0
//==================================================

void FUN_001017a0(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104b09 == '\0') {
    lVar4 = 0x16;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x16);
      if (((int)(uVar2 % 0x16) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x16 + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0xaf);
    DAT_00104b09 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101830 at 00101830
//==================================================

void FUN_00101830(long param_1,long param_2)

{
  byte bVar1;
  undefined1 auVar2 [16];
  ulong uVar3;
  byte bVar4;
  long lVar5;
  long lVar6;
  
  if (DAT_00104b42 == '\0') {
    lVar5 = 0x11;
    uVar3 = 0;
    bVar4 = 0;
    do {
      auVar2._8_8_ = 0;
      auVar2._0_8_ = uVar3;
      lVar6 = uVar3 - (uVar3 / 0x11 +
                      (SUB168(auVar2 * ZEXT816(0xf0f0f0f0f0f0f0f1),8) & 0xfffffffffffffff0));
      bVar1 = *(byte *)(param_2 + lVar6);
      if (((int)lVar6 * (uint)bVar1 & 1) == 0) {
        bVar4 = ~(*(char *)(param_2 + lVar5) + bVar4 ^ bVar1);
      }
      else {
        bVar4 = -(*(char *)(param_2 + lVar5) - bVar4 ^ bVar1);
      }
      bVar4 = bVar4 ^ bVar1;
      *(byte *)(param_1 + -0x11 + lVar5) = bVar4;
      uVar3 = uVar3 + 1;
      lVar5 = lVar5 + 1;
    } while (lVar5 != 0x49);
    DAT_00104b42 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_001018b0 at 001018b0
//==================================================

void FUN_001018b0(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104b84 == '\0') {
    lVar4 = 0x1b;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x1b);
      if (((int)(uVar2 % 0x1b) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x1b + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5c);
    DAT_00104b84 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101930 at 00101930
//==================================================

void FUN_00101930(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104bc6 == '\0') {
    lVar4 = 0x1d;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x1d);
      if (((int)(uVar2 % 0x1d) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x1d + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x5e);
    DAT_00104bc6 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_001019d0 at 001019d0
//==================================================

void FUN_001019d0(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104bf9 == '\0') {
    lVar4 = 0x1b;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x1b);
      if (((int)(uVar2 % 0x1b) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x1b + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x4d);
    DAT_00104bf9 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101a50 at 00101a50
//==================================================

void FUN_00101a50(long param_1,long param_2)

{
  byte bVar1;
  char cVar2;
  long lVar3;
  byte bVar4;
  
  if (DAT_00104c23 == '\0') {
    lVar3 = 0;
    bVar4 = 0;
    do {
      bVar1 = *(byte *)(param_2 + (ulong)((uint)lVar3 & 0xf));
      cVar2 = *(char *)(param_2 + 0x10 + lVar3);
      if (((uint)bVar1 * (uint)lVar3 & 1) == 0) {
        bVar4 = ~(cVar2 + bVar4 ^ bVar1);
      }
      else {
        bVar4 = -(cVar2 - bVar4 ^ bVar1);
      }
      bVar4 = bVar4 ^ bVar1;
      *(byte *)(param_1 + lVar3) = bVar4;
      lVar3 = lVar3 + 1;
    } while (lVar3 != 0x29);
    DAT_00104c23 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101ab0 at 00101ab0
//==================================================

void FUN_00101ab0(long param_1,long param_2)

{
  byte bVar1;
  char cVar2;
  long lVar3;
  byte bVar4;
  
  if (DAT_00104c33 == '\0') {
    lVar3 = 0;
    bVar4 = 0;
    do {
      bVar1 = *(byte *)(param_2 + lVar3);
      cVar2 = *(char *)(param_2 + 0x16 + lVar3);
      if (((uint)bVar1 * (int)lVar3 & 1) == 0) {
        bVar4 = ~(cVar2 + bVar4 ^ bVar1);
      }
      else {
        bVar4 = -(cVar2 - bVar4 ^ bVar1);
      }
      bVar4 = bVar4 ^ bVar1;
      *(byte *)(param_1 + lVar3) = bVar4;
      lVar3 = lVar3 + 1;
    } while (lVar3 != 0xf);
    DAT_00104c33 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101b10 at 00101b10
//==================================================

void FUN_00101b10(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104c54 == '\0') {
    lVar4 = 0x19;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x19);
      if (((int)(uVar2 % 0x19) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x19 + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x39);
    DAT_00104c54 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101ba0 at 00101ba0
//==================================================

void FUN_00101ba0(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104ce0 == '\0') {
    lVar4 = 0x16;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x16);
      if (((int)(uVar2 % 0x16) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x16 + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0xa1);
    DAT_00104ce0 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101c30 at 00101c30
//==================================================

void FUN_00101c30(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104d0f == '\0') {
    lVar4 = 0x16;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x16);
      if (((int)(uVar2 % 0x16) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x16 + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x44);
    DAT_00104d0f = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101cb0 at 00101cb0
//==================================================

void FUN_00101cb0(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104d9b == '\0') {
    lVar4 = 0x13;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x13);
      if (((int)(uVar2 % 0x13) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x13 + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x9e);
    DAT_00104d9b = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101d30 at 00101d30
//==================================================

void FUN_00101d30(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104dd3 == '\0') {
    lVar4 = 0x1b;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x1b);
      if (((int)(uVar2 % 0x1b) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x1b + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x52);
    DAT_00104dd3 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101db0 at 00101db0
//==================================================

void FUN_00101db0(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104e06 == '\0') {
    lVar4 = 0x19;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x19);
      if (((int)(uVar2 % 0x19) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x19 + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x4b);
    DAT_00104e06 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101e40 at 00101e40
//==================================================

void FUN_00101e40(long param_1,long param_2)

{
  byte bVar1;
  char cVar2;
  long lVar3;
  byte bVar4;
  
  if (DAT_00104e23 == '\0') {
    lVar3 = 0;
    bVar4 = 0;
    do {
      bVar1 = *(byte *)(param_2 + lVar3);
      cVar2 = *(char *)(param_2 + 0x1c + lVar3);
      if (((uint)bVar1 * (int)lVar3 & 1) == 0) {
        bVar4 = ~(cVar2 + bVar4 ^ bVar1);
      }
      else {
        bVar4 = -(cVar2 - bVar4 ^ bVar1);
      }
      bVar4 = bVar4 ^ bVar1;
      *(byte *)(param_1 + lVar3) = bVar4;
      lVar3 = lVar3 + 1;
    } while (lVar3 != 0x1c);
    DAT_00104e23 = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101ea0 at 00101ea0
//==================================================

void FUN_00101ea0(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104e5a == '\0') {
    lVar4 = 0x13;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x13);
      if (((int)(uVar2 % 0x13) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x13 + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x49);
    DAT_00104e5a = '\x01';
  }
  return;
}



//==================================================
// Function: FUN_00101f20 at 00101f20
//==================================================

void FUN_00101f20(long param_1,long param_2)

{
  byte bVar1;
  ulong uVar2;
  byte bVar3;
  long lVar4;
  
  if (DAT_00104e84 == '\0') {
    lVar4 = 0x13;
    uVar2 = 0;
    bVar3 = 0;
    do {
      bVar1 = *(byte *)(param_2 + uVar2 % 0x13);
      if (((int)(uVar2 % 0x13) * (uint)bVar1 & 1) == 0) {
        bVar3 = ~(*(char *)(param_2 + lVar4) + bVar3 ^ bVar1);
      }
      else {
        bVar3 = -(*(char *)(param_2 + lVar4) - bVar3 ^ bVar1);
      }
      bVar3 = bVar3 ^ bVar1;
      *(byte *)(param_1 + -0x13 + lVar4) = bVar3;
      uVar2 = uVar2 + 1;
      lVar4 = lVar4 + 1;
    } while (lVar4 != 0x3c);
    DAT_00104e84 = '\x01';
  }
  return;
}



//==================================================
// Function: _DT_FINI at 00101f9c
//==================================================

void _DT_FINI(void)

{
  return;
}


