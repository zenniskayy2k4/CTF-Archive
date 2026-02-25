
//==================================================
// Function: entry at 1000:0000
//==================================================

/* WARNING: Stack frame is not setup normally: Input value of stackpointer is not used */
/* WARNING: This function may have set the stack pointer */

void __cdecl16far entry(void)

{
  code *pcVar1;
  undefined2 uVar2;
  int iVar3;
  char extraout_AL;
  char cVar4;
  undefined1 extraout_AH;
  int iVar5;
  byte bVar7;
  int iVar6;
  uint uVar8;
  undefined1 *puVar9;
  undefined2 *puVar10;
  undefined2 *puVar11;
  int iVar12;
  undefined1 *puVar13;
  
  puVar9 = (undefined1 *)0x40;
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  for (uVar8 = 0; (char)uVar8 < s__Welcome_to_the_80s_AI_image_gen_102a_0000[0xac];
      uVar8 = (uint)(byte)((char)uVar8 + 1)) {
    *(undefined1 *)(uVar8 - 0x308) = *(undefined1 *)(uVar8 + 0xad);
  }
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  iVar5 = 4;
  cVar4 = extraout_AL;
  do {
    cVar4 = cVar4 * '\x02';
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  puVar10 = (undefined2 *)(puVar9 + -2);
  *(uint *)(puVar9 + -2) = CONCAT11(extraout_AH,cVar4 + extraout_AL);
  pcVar1 = (code *)swi(0x21);
  cVar4 = (*pcVar1)();
  uVar2 = *puVar10;
  puVar11 = puVar10 + 1;
  cVar4 = cVar4 + DAT_102a_fcf8;
  uVar8 = (uint)(byte)s__Welcome_to_the_80s_AI_image_gen_102a_0000[0xac];
  do {
    *(byte *)(uVar8 - 0x309) = *(byte *)(uVar8 - 0x309) ^ (byte)uVar2;
    *(char *)(uVar8 - 0x309) = *(char *)(uVar8 - 0x309) + cVar4;
    uVar8 = uVar8 - 1;
  } while (uVar8 != 0);
  iVar5 = 0;
  pcVar1 = (code *)swi(0x21);
  DAT_102a_0177 = (*pcVar1)();
  iVar12 = 1;
  while( true ) {
    bVar7 = (byte)((uint)iVar5 >> 8);
    iVar5 = CONCAT11(bVar7,s__Welcome_to_the_80s_AI_image_gen_102a_0000[0xac]);
    if (iVar5 <= iVar12) break;
    iVar5 = (uint)bVar7 << 8;
    pcVar1 = (code *)swi(0x21);
    (*pcVar1)();
    iVar12 = iVar12 + 2;
  }
  for (iVar12 = 0; bVar7 = (byte)((uint)iVar5 >> 8),
      iVar12 < CONCAT11(bVar7,s__Welcome_to_the_80s_AI_image_gen_102a_0000[0xac]);
      iVar12 = iVar12 + 2) {
    iVar5 = (uint)bVar7 << 8;
    pcVar1 = (code *)swi(0x21);
    (*pcVar1)();
  }
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  DAT_102a_0177 = (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  *(undefined2 *)((int)puVar11 + -2) = 0x115;
  FUN_1000_01c6();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  DAT_102a_0177 = (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  *(undefined2 *)((int)puVar11 + -2) = 0x167;
  FUN_1000_0236();
  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  iVar6 = -0x600;
  puVar13 = (undefined1 *)0x0;
  iVar12 = 0;
  iVar5 = 0;
  do {
    iVar3 = -iVar6;
    if (7 < iVar12) {
      iVar12 = 0;
    }
    if (s__Welcome_to_the_80s_AI_image_gen_102a_0000[0xac] <= (char)iVar5) {
      iVar5 = 0;
    }
    *(undefined2 *)((int)puVar11 + -2) = puVar13;
    *(int *)((int)puVar11 + -4) = iVar5;
    *(byte *)(iVar3 + -0x364) = *(byte *)(iVar3 + -0x364) ^ *(byte *)(iVar12 + -0x310);
    iVar5 = *(int *)((int)puVar11 + -4);
    *(undefined2 *)((int)puVar11 + -2) = *(undefined2 *)((int)puVar11 + -2);
    *(int *)((int)puVar11 + -4) = iVar12;
    *(byte *)(iVar3 + -0x364) = *(byte *)(iVar3 + -0x364) ^ *(byte *)(iVar5 + 0xad);
    iVar12 = *(int *)((int)puVar11 + -4);
    puVar13 = (undefined1 *)*(undefined2 *)((int)puVar11 + -2) + 1;
    *(undefined1 *)*(undefined2 *)((int)puVar11 + -2) = *(undefined1 *)(iVar3 + -0x364);
    iVar12 = iVar12 + 1;
    iVar5 = iVar5 + 1;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  return;
}



//==================================================
// Function: FUN_1000_01c6 at 1000:01c6
//==================================================

undefined4 __cdecl16near FUN_1000_01c6(void)

{
  byte bVar1;
  char cVar2;
  ulong uVar3;
  undefined2 in_AX;
  uint uVar4;
  int iVar5;
  undefined2 in_DX;
  int iVar6;
  int unaff_DI;
  undefined2 unaff_DS;
  
  iVar5 = 0;
  for (iVar6 = 0; bVar1 = *(byte *)(iVar6 + unaff_DI), bVar1 != 0x24; iVar6 = iVar6 + 2) {
    cVar2 = *(char *)(iVar6 + 1 + unaff_DI);
    uVar4 = CONCAT11(cVar2,bVar1);
    if (cVar2 == '$') {
      uVar4 = (uint)bVar1;
    }
    *(undefined1 *)(iVar5 + 0xf6) = *(undefined1 *)(uVar4 % 0x24 + 0xd1);
    uVar3 = ((ulong)uVar4 / 0x24) / 0x24;
    *(undefined1 *)(iVar5 + 0xf7) = *(undefined1 *)((int)(((ulong)uVar4 / 0x24) % 0x24) + 0xd1);
    *(undefined1 *)(iVar5 + 0xf8) = *(undefined1 *)((int)(uVar3 % 0x24) + 0xd1);
    *(undefined1 *)(iVar5 + 0xf9) = *(undefined1 *)((int)((uVar3 / 0x24) % 0x24) + 0xd1);
    iVar5 = iVar5 + 4;
  }
  return CONCAT22(in_DX,in_AX);
}



//==================================================
// Function: FUN_1000_0236 at 1000:0236
//==================================================

void __cdecl16near FUN_1000_0236(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  byte bVar4;
  uint uVar5;
  int iVar6;
  byte bVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  undefined2 unaff_DS;
  bool bVar15;
  bool bVar16;
  
  for (iVar8 = 0; (char)iVar8 < *(char *)0xac; iVar8 = iVar8 + 1) {
    uVar5 = *(uint *)0xfcf0;
    uVar12 = *(uint *)0xfcf2;
    uVar10 = *(uint *)0xfcf4;
    uVar14 = *(uint *)0xfcf6;
    iVar9 = 5;
    do {
      bVar15 = (int)uVar5 < 0;
      uVar5 = uVar5 * 2;
      bVar16 = (int)uVar12 < 0;
      uVar12 = uVar12 << 1 | (uint)bVar15;
      bVar15 = (int)uVar10 < 0;
      uVar10 = uVar10 << 1 | (uint)bVar16;
      uVar14 = uVar14 << 1 | (uint)bVar15;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    iVar6 = uVar5 + *(uint *)0xfcf0;
    uVar5 = (uint)CARRY2(uVar5,*(uint *)0xfcf0);
    uVar2 = uVar12 + *(uint *)0xfcf2;
    uVar13 = uVar2 + uVar5;
    uVar12 = (uint)(CARRY2(uVar12,*(uint *)0xfcf2) || CARRY2(uVar2,uVar5));
    uVar5 = *(uint *)0xfcf4;
    uVar3 = uVar10 + *(uint *)0xfcf4;
    uVar11 = uVar3 + uVar12;
    iVar9 = *(int *)0xfcf6;
    bVar4 = (byte)iVar6;
    bVar15 = CARRY1(bVar4,*(byte *)(iVar8 + 0xad));
    bVar7 = (byte)((uint)iVar6 >> 8);
    uVar2 = (uint)CARRY1(bVar7,bVar15);
    uVar1 = (uint)CARRY2(uVar13,uVar2);
    *(undefined2 *)0xfcf0 = CONCAT11(bVar7 + bVar15,bVar4 + *(byte *)(iVar8 + 0xad));
    *(int *)0xfcf2 = uVar13 + uVar2;
    *(int *)0xfcf4 = uVar11 + uVar1;
    *(int *)0xfcf6 =
         uVar14 + iVar9 + (uint)(CARRY2(uVar10,uVar5) || CARRY2(uVar3,uVar12)) +
         (uint)CARRY2(uVar11,uVar1);
  }
  return;
}


