
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
            (FUN_0010165f,param_2,&stack0x00000008,0,0,param_1,auStack_8);
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
  if (DAT_00104060 == '\0') {
    if (PTR___cxa_finalize_00103ff8 != (undefined *)0x0) {
      FUN_00101140(PTR_LOOP_00104008);
    }
    FUN_00101290();
    DAT_00104060 = 1;
    return;
  }
  return;
}



//==================================================
// Function: FUN_00101349 at 00101349
//==================================================

long FUN_00101349(char *param_1)

{
  bool bVar1;
  FILE *__stream;
  long __off;
  size_t sVar2;
  long in_FS_OFFSET;
  int local_34;
  long local_30;
  char local_18 [8];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __stream = fopen(param_1,"rb");
  if (__stream == (FILE *)0x0) {
    local_30 = -1;
  }
  else {
    local_30 = 0;
    while( true ) {
      sVar2 = fread(local_18,1,1,__stream);
      if (sVar2 != 1) break;
      if (local_18[0] == DAT_00104020) {
        __off = ftell(__stream);
        sVar2 = fread(local_18,1,7,__stream);
        if (sVar2 == 7) {
          bVar1 = true;
          local_34 = 0;
          while ((local_34 < 7 && (bVar1))) {
            if (local_18[local_34] != (&DAT_00104020)[local_34 + 1]) {
              bVar1 = false;
            }
            local_34 = local_34 + 1;
          }
          if (bVar1) {
            fclose(__stream);
            goto LAB_0010149f;
          }
        }
        fseek(__stream,__off,0);
      }
      local_30 = local_30 + 1;
    }
    fclose(__stream);
    local_30 = -1;
  }
LAB_0010149f:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return local_30;
}



//==================================================
// Function: FUN_001014b5 at 001014b5
//==================================================

ulong FUN_001014b5(char *param_1,long param_2)

{
  int iVar1;
  FILE *__stream;
  ulong local_20;
  long local_18;
  
  __stream = fopen(param_1,"rb");
  if (__stream == (FILE *)0x0) {
    local_20 = 0;
  }
  else {
    local_20 = 0xcbf29ce484222325;
    local_18 = 0;
    while( true ) {
      iVar1 = fgetc(__stream);
      if (iVar1 == -1) break;
      if (((param_2 < 0) || (local_18 < param_2)) || (param_2 + 0x3f < local_18)) {
        local_20 = ((long)iVar1 ^ local_20) * 0x100000001b3;
        local_18 = local_18 + 1;
      }
      else {
        local_18 = local_18 + 1;
      }
    }
    fclose(__stream);
    local_20 = local_20 ^ 0xcafebabe00000000;
  }
  return local_20;
}



//==================================================
// Function: FUN_00101583 at 00101583
//==================================================

undefined8 FUN_00101583(long param_1,long param_2,ulong param_3)

{
  undefined8 uVar1;
  long in_FS_OFFSET;
  int local_24;
  ulong local_20;
  byte local_18 [8];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_20 = param_3;
  for (local_24 = 0; local_24 < 8; local_24 = local_24 + 1) {
    local_18[local_24] = (byte)local_20 ^ *(byte *)(param_1 + param_2 + local_24);
    local_20 = local_20 >> 1 | (ulong)((local_20 & 1) != 0) << 0x3f;
  }
  if (((((local_18[0] == 0x42) && (local_18[1] == 'I')) && (local_18[2] == 'T')) &&
      ((local_18[3] == 'S' && (local_18[4] == 'C')))) &&
     ((local_18[5] == 'T' && ((local_18[6] == 'F' && (local_18[7] == '{')))))) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar1;
}



//==================================================
// Function: FUN_0010165f at 0010165f
//==================================================

int FUN_0010165f(int param_1,undefined8 *param_2)

{
  int iVar1;
  long lVar2;
  long lVar3;
  FILE *pFVar4;
  size_t sVar5;
  void *__ptr;
  size_t sVar6;
  undefined8 *puVar7;
  long in_FS_OFFSET;
  byte bVar8;
  int local_458;
  char local_418 [16];
  undefined8 local_408 [127];
  long local_10;
  
  bVar8 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  lVar2 = FUN_00101349(*param_2);
  if (lVar2 == -1) {
    iVar1 = 1;
  }
  else {
    lVar3 = FUN_001014b5(*param_2,lVar2);
    if (lVar3 == 0) {
      iVar1 = 1;
    }
    else {
      pFVar4 = fopen((char *)*param_2,"rb");
      if (pFVar4 == (FILE *)0x0) {
        iVar1 = 1;
      }
      else {
        fseek(pFVar4,0,2);
        sVar5 = ftell(pFVar4);
        fseek(pFVar4,0,0);
        __ptr = malloc(sVar5);
        if (__ptr == (void *)0x0) {
          fclose(pFVar4);
          iVar1 = 1;
        }
        else {
          sVar6 = fread(__ptr,1,sVar5,pFVar4);
          if (sVar6 == sVar5) {
            fclose(pFVar4);
            if (lVar2 + 0x3f < (long)sVar5) {
              iVar1 = FUN_00101583(__ptr,lVar2,lVar3);
              if (iVar1 == 0) {
                free(__ptr);
                iVar1 = 1;
                goto LAB_00101a95;
              }
              memset((void *)((long)__ptr + lVar2),0,0x40);
            }
            iVar1 = unlink((char *)*param_2);
            if (iVar1 == 0) {
              pFVar4 = fopen((char *)*param_2,"wb");
              if (pFVar4 == (FILE *)0x0) {
                free(__ptr);
                iVar1 = 1;
              }
              else {
                fwrite(__ptr,1,sVar5,pFVar4);
                fclose(pFVar4);
                free(__ptr);
                chmod((char *)*param_2,0x1ed);
                builtin_strncpy(local_418,"gcc ",5);
                local_418[5] = '\0';
                local_418[6] = '\0';
                local_418[7] = '\0';
                local_418[8] = '\0';
                local_418[9] = '\0';
                local_418[10] = '\0';
                local_418[0xb] = '\0';
                local_418[0xc] = '\0';
                local_418[0xd] = '\0';
                local_418[0xe] = '\0';
                local_418[0xf] = '\0';
                puVar7 = local_408;
                for (lVar2 = 0x7e; lVar2 != 0; lVar2 = lVar2 + -1) {
                  *puVar7 = 0;
                  puVar7 = puVar7 + (ulong)bVar8 * -2 + 1;
                }
                for (local_458 = 1; local_458 < param_1; local_458 = local_458 + 1) {
                  strcat(local_418,(char *)param_2[local_458]);
                  sVar5 = strlen(local_418);
                  (local_418 + sVar5)[0] = ' ';
                  (local_418 + sVar5)[1] = '\0';
                  strcmp((char *)param_2[local_458],"-o");
                }
                iVar1 = system(local_418);
                if (iVar1 == 0) {
                  iVar1 = 0;
                }
              }
            }
            else {
              free(__ptr);
              iVar1 = 1;
            }
          }
          else {
            free(__ptr);
            fclose(pFVar4);
            iVar1 = 1;
          }
        }
      }
    }
  }
LAB_00101a95:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}



//==================================================
// Function: _DT_FINI at 00101aac
//==================================================

void _DT_FINI(void)

{
  return;
}


