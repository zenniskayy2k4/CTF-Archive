
//==================================================
// Function: _DT_INIT at 00401000
//==================================================

void _DT_INIT(void)

{
  if (PTR___gmon_start___00408fe0 != (undefined *)0x0) {
    (*(code *)PTR___gmon_start___00408fe0)();
  }
  return;
}



//==================================================
// Function: FUN_00401020 at 00401020
//==================================================

void FUN_00401020(void)

{
  (*(code *)PTR_00408ff8)();
  return;
}



//==================================================
// Function: FUN_004010c0 at 004010c0
//==================================================

undefined8 FUN_004010c0(int param_1,undefined8 *param_2)

{
  undefined1 *puVar1;
  int iVar2;
  ulonglong uVar3;
  long lVar4;
  long lVar5;
  undefined1 *puVar6;
  ulong uVar7;
  int iVar8;
  undefined1 *puVar9;
  ulong *puVar10;
  long local_4f8 [3];
  char *local_4e0;
  ulong local_4d8 [5];
  undefined1 local_4b0 [360];
  ulong local_348 [50];
  ulong local_1b8 [51];
  
  if (param_1 == 2) {
    uVar3 = strtoull((char *)param_2[1],&local_4e0,0x10);
    if ((*local_4e0 == '\0') || (*local_4e0 == '\n')) {
      iVar8 = 3;
      __printf_chk(2,"Calibrating...");
      fflush(stdout);
      while (iVar2 = FUN_00406298(), iVar2 == 0) {
        iVar8 = iVar8 + -1;
        if (iVar8 == 0) {
          puts("FAILED");
          fwrite("Your CPU does not support the required features.\n",1,0x31,stderr);
          fwrite("This binary requires speculative execution side-channels.\n",1,0x3a,stderr);
          return 1;
        }
      }
      puVar10 = local_4d8;
      iVar8 = 0;
      puts("OK");
      puVar9 = local_4b0;
      puts("Computing...");
      do {
        while( true ) {
          lVar4 = FUN_00405b37();
          *(long *)(puVar9 + -0x28) = lVar4;
          if (3 < iVar8) break;
          iVar8 = iVar8 + 1;
          puVar9 = puVar9 + 8;
        }
        iVar2 = 0;
        puVar1 = puVar9 + -0x28;
        do {
          puVar6 = puVar1;
          if (lVar4 == *(long *)(puVar6 + -0x20)) {
            iVar2 = iVar2 + 1;
          }
          puVar1 = puVar6 + 8;
        } while (puVar6 + 8 != puVar9);
        if (2 < iVar2) {
          __printf_chk(2,"compute(0x%016lx) = 0x%016lx\n",uVar3,lVar4);
          return 0;
        }
        iVar8 = iVar8 + 1;
        puVar9 = puVar6 + 0x10;
      } while (iVar8 != 0x32);
      iVar8 = 0;
      do {
        uVar7 = *puVar10;
        lVar4 = (long)iVar8;
        if (0 < iVar8) {
          while( true ) {
            lVar5 = 0;
            while (local_1b8[lVar5] != uVar7) {
              lVar5 = lVar5 + 1;
              if (lVar4 == lVar5) goto LAB_00401270;
            }
            puVar10 = puVar10 + 1;
            local_348[(int)lVar5] = local_348[(int)lVar5] + 1;
            if (local_348 == puVar10) break;
            uVar7 = *puVar10;
          }
          break;
        }
LAB_00401270:
        puVar10 = puVar10 + 1;
        local_1b8[lVar4] = uVar7;
        iVar8 = iVar8 + 1;
        local_348[lVar4] = 1;
      } while (local_348 != puVar10);
      for (lVar4 = 1; (int)lVar4 < iVar8; lVar4 = lVar4 + 1) {
        if (local_348[0] < local_348[lVar4]) {
          local_1b8[0] = local_1b8[lVar4];
          local_348[0] = local_348[lVar4];
        }
      }
      __printf_chk(2,"compute(0x%016lx) = 0x%016lx (confidence: %lu/%d)\n",uVar3,local_1b8[0],
                   local_348[0],0x32);
      return 0;
    }
    fwrite("Error: Invalid hex input\n",1,0x19,stderr);
  }
  else {
    __fprintf_chk(stderr,2,"Usage: %s <hex_input>\n",*param_2);
    __fprintf_chk(stderr,2,"Example: %s 0xDEADBEEFCAFEBABE\n",*param_2);
  }
  return 1;
}



//==================================================
// Function: entry at 00401350
//==================================================

void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00408fd8)
            (FUN_004010c0,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



//==================================================
// Function: FUN_00401380 at 00401380
//==================================================

void FUN_00401380(void)

{
  return;
}



//==================================================
// Function: FUN_00401390 at 00401390
//==================================================

/* WARNING: Removing unreachable block (ram,0x0040139d) */
/* WARNING: Removing unreachable block (ram,0x004013a7) */

void FUN_00401390(void)

{
  return;
}



//==================================================
// Function: FUN_004013c0 at 004013c0
//==================================================

/* WARNING: Removing unreachable block (ram,0x004013df) */
/* WARNING: Removing unreachable block (ram,0x004013e9) */

void FUN_004013c0(void)

{
  return;
}



//==================================================
// Function: _FINI_0 at 00401400
//==================================================

void _FINI_0(void)

{
  if (DAT_0042f328 == '\0') {
    FUN_00401390();
    DAT_0042f328 = 1;
    return;
  }
  return;
}



//==================================================
// Function: FUN_00401440 at 00401440
//==================================================

undefined8 FUN_00401440(void)

{
  clflush(0x80);
  return 0;
}



//==================================================
// Function: FUN_00401681 at 00401681
//==================================================

void FUN_00401681(void)

{
  clflush(DAT_0040b000);
  clflush(DAT_0040b240);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004017a1 at 004017a1
//==================================================

void FUN_004017a1(void)

{
  clflush(DAT_0040b480);
  clflush(DAT_0040b6c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004018a1 at 004018a1
//==================================================

void FUN_004018a1(void)

{
  clflush(DAT_0040b900);
  clflush(DAT_0040bb40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004019a1 at 004019a1
//==================================================

void FUN_004019a1(void)

{
  clflush(DAT_0040bd80);
  clflush(DAT_0040bfc0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00401aa1 at 00401aa1
//==================================================

void FUN_00401aa1(void)

{
  clflush(DAT_0040c200);
  clflush(DAT_0040c440);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00401ba1 at 00401ba1
//==================================================

void FUN_00401ba1(void)

{
  clflush(DAT_0040c680);
  clflush(DAT_0040c8c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00401ca1 at 00401ca1
//==================================================

void FUN_00401ca1(void)

{
  clflush(DAT_0040cb00);
  clflush(DAT_0040cd40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00401da1 at 00401da1
//==================================================

void FUN_00401da1(void)

{
  clflush(DAT_0040cf80);
  clflush(DAT_0040d1c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00401ea1 at 00401ea1
//==================================================

void FUN_00401ea1(void)

{
  clflush(DAT_0040d400);
  clflush(DAT_0040d640);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00401fa1 at 00401fa1
//==================================================

void FUN_00401fa1(void)

{
  clflush(DAT_0040d880);
  clflush(DAT_0040dac0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004020a1 at 004020a1
//==================================================

void FUN_004020a1(void)

{
  clflush(DAT_0040dd00);
  clflush(DAT_0040df40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004021a1 at 004021a1
//==================================================

void FUN_004021a1(void)

{
  clflush(DAT_0040e180);
  clflush(DAT_0040e3c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004022a1 at 004022a1
//==================================================

void FUN_004022a1(void)

{
  clflush(DAT_0040e600);
  clflush(DAT_0040e840);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004023a1 at 004023a1
//==================================================

void FUN_004023a1(void)

{
  clflush(DAT_0040ea80);
  clflush(DAT_0040ecc0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004024a1 at 004024a1
//==================================================

void FUN_004024a1(void)

{
  clflush(DAT_0040ef00);
  clflush(DAT_0040f140);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004025a1 at 004025a1
//==================================================

void FUN_004025a1(void)

{
  clflush(DAT_0040f380);
  clflush(DAT_0040f5c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004026a1 at 004026a1
//==================================================

void FUN_004026a1(void)

{
  clflush(DAT_0040f800);
  clflush(DAT_0040fa40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004027a1 at 004027a1
//==================================================

void FUN_004027a1(void)

{
  clflush(DAT_0040fc80);
  clflush(DAT_0040fec0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004028a1 at 004028a1
//==================================================

void FUN_004028a1(void)

{
  clflush(DAT_00410100);
  clflush(DAT_00410340);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004029a1 at 004029a1
//==================================================

void FUN_004029a1(void)

{
  clflush(DAT_00410580);
  clflush(DAT_004107c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00402aa1 at 00402aa1
//==================================================

void FUN_00402aa1(void)

{
  clflush(DAT_00410a00);
  clflush(DAT_00410c40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00402ba1 at 00402ba1
//==================================================

void FUN_00402ba1(void)

{
  clflush(DAT_00410e80);
  clflush(DAT_004110c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00402ca1 at 00402ca1
//==================================================

void FUN_00402ca1(void)

{
  clflush(DAT_00411300);
  clflush(DAT_00411540);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00402da1 at 00402da1
//==================================================

void FUN_00402da1(void)

{
  clflush(DAT_00411780);
  clflush(DAT_004119c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00402ea1 at 00402ea1
//==================================================

void FUN_00402ea1(void)

{
  clflush(DAT_00411c00);
  clflush(DAT_00411e40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00402fa1 at 00402fa1
//==================================================

void FUN_00402fa1(void)

{
  clflush(DAT_00412080);
  clflush(DAT_004122c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004030a1 at 004030a1
//==================================================

void FUN_004030a1(void)

{
  clflush(DAT_00412500);
  clflush(DAT_00412740);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004031a1 at 004031a1
//==================================================

void FUN_004031a1(void)

{
  clflush(DAT_00412980);
  clflush(DAT_00412bc0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004032a1 at 004032a1
//==================================================

void FUN_004032a1(void)

{
  clflush(DAT_00412e00);
  clflush(DAT_00413040);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004033a1 at 004033a1
//==================================================

void FUN_004033a1(void)

{
  clflush(DAT_00413280);
  clflush(DAT_004134c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004034a1 at 004034a1
//==================================================

void FUN_004034a1(void)

{
  clflush(DAT_00413700);
  clflush(DAT_00413940);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004035a1 at 004035a1
//==================================================

void FUN_004035a1(void)

{
  clflush(DAT_00413b80);
  clflush(DAT_00413dc0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004036a1 at 004036a1
//==================================================

void FUN_004036a1(void)

{
  clflush(DAT_00414000);
  clflush(DAT_00414240);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004037a1 at 004037a1
//==================================================

void FUN_004037a1(void)

{
  clflush(DAT_00414480);
  clflush(DAT_004146c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004038a1 at 004038a1
//==================================================

void FUN_004038a1(void)

{
  clflush(DAT_00414900);
  clflush(DAT_00414b40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004039a1 at 004039a1
//==================================================

void FUN_004039a1(void)

{
  clflush(DAT_00414d80);
  clflush(DAT_00414fc0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00403aa1 at 00403aa1
//==================================================

void FUN_00403aa1(void)

{
  clflush(DAT_00415200);
  clflush(DAT_00415440);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00403ba1 at 00403ba1
//==================================================

void FUN_00403ba1(void)

{
  clflush(DAT_00415680);
  clflush(DAT_004158c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00403ca1 at 00403ca1
//==================================================

void FUN_00403ca1(void)

{
  clflush(DAT_00415b00);
  clflush(DAT_00415d40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00403da1 at 00403da1
//==================================================

void FUN_00403da1(void)

{
  clflush(DAT_00415f80);
  clflush(DAT_004161c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00403ea1 at 00403ea1
//==================================================

void FUN_00403ea1(void)

{
  clflush(DAT_00416400);
  clflush(DAT_00416640);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00403fa1 at 00403fa1
//==================================================

void FUN_00403fa1(void)

{
  clflush(DAT_00416880);
  clflush(DAT_00416ac0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004040a1 at 004040a1
//==================================================

void FUN_004040a1(void)

{
  clflush(DAT_00416d00);
  clflush(DAT_00416f40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004041a1 at 004041a1
//==================================================

void FUN_004041a1(void)

{
  clflush(DAT_00417180);
  clflush(DAT_004173c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004042a1 at 004042a1
//==================================================

void FUN_004042a1(void)

{
  clflush(DAT_00417600);
  clflush(DAT_00417840);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004043a1 at 004043a1
//==================================================

void FUN_004043a1(void)

{
  clflush(DAT_00417a80);
  clflush(DAT_00417cc0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004044a1 at 004044a1
//==================================================

void FUN_004044a1(void)

{
  clflush(DAT_00417f00);
  clflush(DAT_00418140);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004045a1 at 004045a1
//==================================================

void FUN_004045a1(void)

{
  clflush(DAT_00418380);
  clflush(DAT_004185c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004046a1 at 004046a1
//==================================================

void FUN_004046a1(void)

{
  clflush(DAT_00418800);
  clflush(DAT_00418a40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004047a1 at 004047a1
//==================================================

void FUN_004047a1(void)

{
  clflush(DAT_00418c80);
  clflush(DAT_00418ec0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004048a1 at 004048a1
//==================================================

void FUN_004048a1(void)

{
  clflush(DAT_00419100);
  clflush(DAT_00419340);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004049a1 at 004049a1
//==================================================

void FUN_004049a1(void)

{
  clflush(DAT_00419580);
  clflush(DAT_004197c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00404aa1 at 00404aa1
//==================================================

void FUN_00404aa1(void)

{
  clflush(DAT_00419a00);
  clflush(DAT_00419c40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00404ba1 at 00404ba1
//==================================================

void FUN_00404ba1(void)

{
  clflush(DAT_00419e80);
  clflush(DAT_0041a0c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00404ca1 at 00404ca1
//==================================================

void FUN_00404ca1(void)

{
  clflush(DAT_0041a300);
  clflush(DAT_0041a540);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00404da1 at 00404da1
//==================================================

void FUN_00404da1(void)

{
  clflush(DAT_0041a780);
  clflush(DAT_0041a9c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00404ea1 at 00404ea1
//==================================================

void FUN_00404ea1(void)

{
  clflush(DAT_0041ac00);
  clflush(DAT_0041ae40);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_00404fa1 at 00404fa1
//==================================================

void FUN_00404fa1(void)

{
  clflush(DAT_0041b080);
  clflush(DAT_0041b2c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004050a1 at 004050a1
//==================================================

void FUN_004050a1(void)

{
  clflush(DAT_0041b500);
  clflush(DAT_0041b740);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004051a1 at 004051a1
//==================================================

void FUN_004051a1(void)

{
  clflush(DAT_0041b980);
  clflush(DAT_0041bbc0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004052a1 at 004052a1
//==================================================

void FUN_004052a1(void)

{
  clflush(DAT_0041be00);
  clflush(DAT_0041c040);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004053a1 at 004053a1
//==================================================

void FUN_004053a1(void)

{
  clflush(DAT_0041c280);
  clflush(DAT_0041c4c0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004054a1 at 004054a1
//==================================================

void FUN_004054a1(void)

{
  clflush(DAT_0041c700);
  clflush(DAT_0041c940);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004055a1 at 004055a1
//==================================================

void FUN_004055a1(void)

{
  clflush(DAT_0041cb80);
  clflush(DAT_0041cdc0);
                    /* WARNING: Subroutine does not return */
  FUN_00401440();
}



//==================================================
// Function: FUN_004056a1 at 004056a1
//==================================================

ulong FUN_004056a1(undefined8 param_1)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  
  uVar1 = FUN_00401681(param_1);
  lVar2 = FUN_004017a1(param_1);
  lVar3 = FUN_004018a1(param_1);
  lVar4 = FUN_004019a1(param_1);
  lVar5 = FUN_00401aa1(param_1);
  lVar6 = FUN_00401ba1(param_1);
  lVar7 = FUN_00401ca1(param_1);
  lVar8 = FUN_00401da1(param_1);
  return uVar1 | lVar2 << 1 | lVar3 << 2 | lVar4 << 3 | lVar5 << 4 | lVar6 << 5 | lVar7 << 6 |
         lVar8 << 7;
}



//==================================================
// Function: FUN_0040572c at 0040572c
//==================================================

ulong FUN_0040572c(undefined8 param_1)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  
  uVar1 = FUN_00401ea1(param_1);
  lVar2 = FUN_00401fa1(param_1);
  lVar3 = FUN_004020a1(param_1);
  lVar4 = FUN_004021a1(param_1);
  lVar5 = FUN_004022a1(param_1);
  lVar6 = FUN_004023a1(param_1);
  lVar7 = FUN_004024a1(param_1);
  lVar8 = FUN_004025a1(param_1);
  return uVar1 | lVar2 << 1 | lVar3 << 2 | lVar4 << 3 | lVar5 << 4 | lVar6 << 5 | lVar7 << 6 |
         lVar8 << 7;
}



//==================================================
// Function: FUN_004057b7 at 004057b7
//==================================================

ulong FUN_004057b7(undefined8 param_1)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  
  uVar1 = FUN_004026a1(param_1);
  lVar2 = FUN_004027a1(param_1);
  lVar3 = FUN_004028a1(param_1);
  lVar4 = FUN_004029a1(param_1);
  lVar5 = FUN_00402aa1(param_1);
  lVar6 = FUN_00402ba1(param_1);
  lVar7 = FUN_00402ca1(param_1);
  lVar8 = FUN_00402da1(param_1);
  return uVar1 | lVar2 << 1 | lVar3 << 2 | lVar4 << 3 | lVar5 << 4 | lVar6 << 5 | lVar7 << 6 |
         lVar8 << 7;
}



//==================================================
// Function: FUN_00405842 at 00405842
//==================================================

ulong FUN_00405842(undefined8 param_1)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  
  uVar1 = FUN_00402ea1(param_1);
  lVar2 = FUN_00402fa1(param_1);
  lVar3 = FUN_004030a1(param_1);
  lVar4 = FUN_004031a1(param_1);
  lVar5 = FUN_004032a1(param_1);
  lVar6 = FUN_004033a1(param_1);
  lVar7 = FUN_004034a1(param_1);
  lVar8 = FUN_004035a1(param_1);
  return uVar1 | lVar2 << 1 | lVar3 << 2 | lVar4 << 3 | lVar5 << 4 | lVar6 << 5 | lVar7 << 6 |
         lVar8 << 7;
}



//==================================================
// Function: FUN_004058cd at 004058cd
//==================================================

ulong FUN_004058cd(undefined8 param_1)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  
  uVar1 = FUN_004036a1(param_1);
  lVar2 = FUN_004037a1(param_1);
  lVar3 = FUN_004038a1(param_1);
  lVar4 = FUN_004039a1(param_1);
  lVar5 = FUN_00403aa1(param_1);
  lVar6 = FUN_00403ba1(param_1);
  lVar7 = FUN_00403ca1(param_1);
  lVar8 = FUN_00403da1(param_1);
  return uVar1 | lVar2 << 1 | lVar3 << 2 | lVar4 << 3 | lVar5 << 4 | lVar6 << 5 | lVar7 << 6 |
         lVar8 << 7;
}



//==================================================
// Function: FUN_00405958 at 00405958
//==================================================

ulong FUN_00405958(undefined8 param_1)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  
  uVar1 = FUN_00403ea1(param_1);
  lVar2 = FUN_00403fa1(param_1);
  lVar3 = FUN_004040a1(param_1);
  lVar4 = FUN_004041a1(param_1);
  lVar5 = FUN_004042a1(param_1);
  lVar6 = FUN_004043a1(param_1);
  lVar7 = FUN_004044a1(param_1);
  lVar8 = FUN_004045a1(param_1);
  return uVar1 | lVar2 << 1 | lVar3 << 2 | lVar4 << 3 | lVar5 << 4 | lVar6 << 5 | lVar7 << 6 |
         lVar8 << 7;
}



//==================================================
// Function: FUN_004059e3 at 004059e3
//==================================================

ulong FUN_004059e3(undefined8 param_1)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  
  uVar1 = FUN_004046a1(param_1);
  lVar2 = FUN_004047a1(param_1);
  lVar3 = FUN_004048a1(param_1);
  lVar4 = FUN_004049a1(param_1);
  lVar5 = FUN_00404aa1(param_1);
  lVar6 = FUN_00404ba1(param_1);
  lVar7 = FUN_00404ca1(param_1);
  lVar8 = FUN_00404da1(param_1);
  return uVar1 | lVar2 << 1 | lVar3 << 2 | lVar4 << 3 | lVar5 << 4 | lVar6 << 5 | lVar7 << 6 |
         lVar8 << 7;
}



//==================================================
// Function: FUN_00405a6e at 00405a6e
//==================================================

ulong FUN_00405a6e(undefined8 param_1)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  
  uVar1 = FUN_00404ea1(param_1);
  lVar2 = FUN_00404fa1(param_1);
  lVar3 = FUN_004050a1(param_1);
  lVar4 = FUN_004051a1(param_1);
  lVar5 = FUN_004052a1(param_1);
  lVar6 = FUN_004053a1(param_1);
  lVar7 = FUN_004054a1(param_1);
  lVar8 = FUN_004055a1(param_1);
  return uVar1 | lVar2 << 1 | lVar3 << 2 | lVar4 << 3 | lVar5 << 4 | lVar6 << 5 | lVar7 << 6 |
         lVar8 << 7;
}



//==================================================
// Function: FUN_00405af9 at 00405af9
//==================================================

ulong FUN_00405af9(ulong param_1)

{
  ulong uVar1;
  ulong uVar2;
  
  uVar1 = 0;
  uVar2 = 0;
  do {
    if ((param_1 >> ((ulong)(byte)(&DAT_0042f280)[uVar2] & 0x3f) & 1) != 0) {
      uVar1 = uVar1 | 1L << (uVar2 & 0x3f);
    }
    uVar2 = uVar2 + 1;
  } while (uVar2 < 0x40);
  return uVar1;
}



//==================================================
// Function: FUN_00405b37 at 00405b37
//==================================================

ulong FUN_00405b37(ulong param_1)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  ulong uVar9;
  
  param_1 = param_1 ^ DAT_0042f2c0;
  uVar1 = FUN_004056a1(param_1 & 0xff);
  lVar2 = FUN_0040572c(param_1 >> 8 & 0xff);
  lVar3 = FUN_004057b7(param_1 >> 0x10 & 0xff);
  lVar4 = FUN_00405842(param_1 >> 0x18 & 0xff);
  lVar5 = FUN_004058cd(param_1 >> 0x20 & 0xff);
  lVar6 = FUN_00405958(param_1 >> 0x28 & 0xff);
  lVar7 = FUN_004059e3(param_1 >> 0x30 & 0xff);
  lVar8 = FUN_00405a6e(param_1 >> 0x38);
  uVar1 = FUN_00405af9(uVar1 | lVar2 << 8 | lVar3 << 0x10 | lVar4 << 0x18 | lVar5 << 0x20 |
                       lVar6 << 0x28 | lVar7 << 0x30 | lVar8 << 0x38);
  uVar1 = uVar1 ^ DAT_0042f2c8;
  uVar9 = FUN_004056a1(uVar1 & 0xff);
  lVar2 = FUN_0040572c(uVar1 >> 8 & 0xff);
  lVar3 = FUN_004057b7(uVar1 >> 0x10 & 0xff);
  lVar4 = FUN_00405842(uVar1 >> 0x18 & 0xff);
  lVar5 = FUN_004058cd(uVar1 >> 0x20 & 0xff);
  lVar6 = FUN_00405958(uVar1 >> 0x28 & 0xff);
  lVar7 = FUN_004059e3(uVar1 >> 0x30 & 0xff);
  lVar8 = FUN_00405a6e(uVar1 >> 0x38);
  uVar1 = FUN_00405af9(uVar9 | lVar2 << 8 | lVar3 << 0x10 | lVar4 << 0x18 | lVar5 << 0x20 |
                       lVar6 << 0x28 | lVar7 << 0x30 | lVar8 << 0x38);
  uVar1 = uVar1 ^ DAT_0042f2d0;
  uVar9 = FUN_004056a1(uVar1 & 0xff);
  lVar2 = FUN_0040572c(uVar1 >> 8 & 0xff);
  lVar3 = FUN_004057b7(uVar1 >> 0x10 & 0xff);
  lVar4 = FUN_00405842(uVar1 >> 0x18 & 0xff);
  lVar5 = FUN_004058cd(uVar1 >> 0x20 & 0xff);
  lVar6 = FUN_00405958(uVar1 >> 0x28 & 0xff);
  lVar7 = FUN_004059e3(uVar1 >> 0x30 & 0xff);
  lVar8 = FUN_00405a6e(uVar1 >> 0x38);
  uVar1 = FUN_00405af9(uVar9 | lVar2 << 8 | lVar3 << 0x10 | lVar4 << 0x18 | lVar5 << 0x20 |
                       lVar6 << 0x28 | lVar7 << 0x30 | lVar8 << 0x38);
  uVar1 = uVar1 ^ DAT_0042f2d8;
  uVar9 = FUN_004056a1(uVar1 & 0xff);
  lVar2 = FUN_0040572c(uVar1 >> 8 & 0xff);
  lVar3 = FUN_004057b7(uVar1 >> 0x10 & 0xff);
  lVar4 = FUN_00405842(uVar1 >> 0x18 & 0xff);
  lVar5 = FUN_004058cd(uVar1 >> 0x20 & 0xff);
  lVar6 = FUN_00405958(uVar1 >> 0x28 & 0xff);
  lVar7 = FUN_004059e3(uVar1 >> 0x30 & 0xff);
  lVar8 = FUN_00405a6e(uVar1 >> 0x38);
  uVar1 = FUN_00405af9(uVar9 | lVar2 << 8 | lVar3 << 0x10 | lVar4 << 0x18 | lVar5 << 0x20 |
                       lVar6 << 0x28 | lVar7 << 0x30 | lVar8 << 0x38);
  uVar1 = uVar1 ^ DAT_0042f2e0;
  uVar9 = FUN_004056a1(uVar1 & 0xff);
  lVar2 = FUN_0040572c(uVar1 >> 8 & 0xff);
  lVar3 = FUN_004057b7(uVar1 >> 0x10 & 0xff);
  lVar4 = FUN_00405842(uVar1 >> 0x18 & 0xff);
  lVar5 = FUN_004058cd(uVar1 >> 0x20 & 0xff);
  lVar6 = FUN_00405958(uVar1 >> 0x28 & 0xff);
  lVar7 = FUN_004059e3(uVar1 >> 0x30 & 0xff);
  lVar8 = FUN_00405a6e(uVar1 >> 0x38);
  uVar1 = FUN_00405af9(uVar9 | lVar2 << 8 | lVar3 << 0x10 | lVar4 << 0x18 | lVar5 << 0x20 |
                       lVar6 << 0x28 | lVar7 << 0x30 | lVar8 << 0x38);
  uVar1 = uVar1 ^ DAT_0042f2e8;
  uVar9 = FUN_004056a1(uVar1 & 0xff);
  lVar2 = FUN_0040572c(uVar1 >> 8 & 0xff);
  lVar3 = FUN_004057b7(uVar1 >> 0x10 & 0xff);
  lVar4 = FUN_00405842(uVar1 >> 0x18 & 0xff);
  lVar5 = FUN_004058cd(uVar1 >> 0x20 & 0xff);
  lVar6 = FUN_00405958(uVar1 >> 0x28 & 0xff);
  lVar7 = FUN_004059e3(uVar1 >> 0x30 & 0xff);
  lVar8 = FUN_00405a6e(uVar1 >> 0x38);
  uVar1 = FUN_00405af9(uVar9 | lVar2 << 8 | lVar3 << 0x10 | lVar4 << 0x18 | lVar5 << 0x20 |
                       lVar6 << 0x28 | lVar7 << 0x30 | lVar8 << 0x38);
  uVar1 = uVar1 ^ DAT_0042f2f0;
  uVar9 = FUN_004056a1(uVar1 & 0xff);
  lVar2 = FUN_0040572c(uVar1 >> 8 & 0xff);
  lVar3 = FUN_004057b7(uVar1 >> 0x10 & 0xff);
  lVar4 = FUN_00405842(uVar1 >> 0x18 & 0xff);
  lVar5 = FUN_004058cd(uVar1 >> 0x20 & 0xff);
  lVar6 = FUN_00405958(uVar1 >> 0x28 & 0xff);
  lVar7 = FUN_004059e3(uVar1 >> 0x30 & 0xff);
  lVar8 = FUN_00405a6e(uVar1 >> 0x38);
  uVar1 = FUN_00405af9(uVar9 | lVar2 << 8 | lVar3 << 0x10 | lVar4 << 0x18 | lVar5 << 0x20 |
                       lVar6 << 0x28 | lVar7 << 0x30 | lVar8 << 0x38);
  uVar1 = uVar1 ^ DAT_0042f2f8;
  uVar9 = FUN_004056a1(uVar1 & 0xff);
  lVar2 = FUN_0040572c(uVar1 >> 8 & 0xff);
  lVar3 = FUN_004057b7(uVar1 >> 0x10 & 0xff);
  lVar4 = FUN_00405842(uVar1 >> 0x18 & 0xff);
  lVar5 = FUN_004058cd(uVar1 >> 0x20 & 0xff);
  lVar6 = FUN_00405958(uVar1 >> 0x28 & 0xff);
  lVar7 = FUN_004059e3(uVar1 >> 0x30 & 0xff);
  lVar8 = FUN_00405a6e(uVar1 >> 0x38);
  return uVar9 | lVar2 << 8 | lVar3 << 0x10 | lVar4 << 0x18 | lVar5 << 0x20 | lVar6 << 0x28 |
         lVar7 << 0x30 | lVar8 << 0x38;
}



//==================================================
// Function: FUN_00406298 at 00406298
//==================================================

bool FUN_00406298(void)

{
  byte bVar1;
  ulong uVar2;
  ulong uVar3;
  ulong uVar4;
  ulong uVar5;
  long lVar6;
  
  uVar5 = 0;
  lVar6 = 100;
  do {
    uVar2 = rdtsc();
    clflush(DAT_0040b000);
    clflush(DAT_0040b240);
    bVar1 = DAT_0040b000;
    if ((uVar2 & 0x80) != 0) {
      bVar1 = DAT_0040b240;
    }
    rdtscp();
    rdtscp();
    uVar3 = CONCAT71((int7)((uVar2 & 0xffffffff00000000) >> 8),DAT_0040b000) -
            ((ulong)bVar1 | uVar2 & 0xffffffff00000000);
    rdtscp();
    rdtscp();
    uVar4 = CONCAT71((int7)(uVar3 >> 8),DAT_0040b240) - uVar3;
    if ((uVar2 & 0x80) == 0) {
      if (uVar3 < uVar4) goto LAB_0040634a;
    }
    else if (uVar4 < uVar3) {
LAB_0040634a:
      uVar5 = uVar5 + 1;
    }
    lVar6 = lVar6 + -1;
    if (lVar6 == 0) {
      return 0x45 < uVar5;
    }
  } while( true );
}



//==================================================
// Function: _DT_FINI at 00406370
//==================================================

void _DT_FINI(void)

{
  return;
}


