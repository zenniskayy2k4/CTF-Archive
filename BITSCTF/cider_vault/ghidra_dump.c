
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
  (*(code *)PTR_00103f68)();
  return;
}



//==================================================
// Function: FUN_00101100 at 00101100
//==================================================

void FUN_00101100(void)

{
  (*(code *)PTR___cxa_finalize_00103ff8)();
  return;
}



//==================================================
// Function: main at 001011e0
//==================================================

void main(void)

{
  long lVar1;
  undefined8 *puVar2;
  uint uVar3;
  uint uVar4;
  long *plVar5;
  undefined8 uVar6;
  ssize_t sVar7;
  ulong uVar8;
  void *pvVar9;
  undefined8 *puVar10;
  size_t sVar11;
  int iVar12;
  long *plVar13;
  ulong uVar14;
  long lVar15;
  int iVar16;
  
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts("\x1b[38;5;213mstorybook-workshop\x1b[0m");
  puts("\x1b[38;5;117mOnce upon a midnight, the workshop lamp stayed on.\x1b[0m");
  puts("\x1b[38;5;117mPages still wake when someone whispers to the book.\x1b[0m");
  puts("\x1b[38;5;228mFind the hidden ending before the moonlight fades.\x1b[0m");
LAB_00101268:
  plVar13 = &vats;
  __printf_chk(1,&DAT_00102108);
  plVar5 = &vats;
  iVar12 = 0;
  do {
    iVar16 = iVar12 + 1;
    if (*plVar5 != 0) {
      iVar16 = iVar12 + 2;
      iVar12 = iVar12 + 1;
    }
    plVar5 = plVar5 + 2;
  } while (plVar5 != (long *)&_end);
  __printf_chk(1,&DAT_0010233d,iVar16);
  iVar12 = 0;
  do {
    iVar12 = (iVar12 + 1) - (uint)(*plVar13 == 0);
    plVar13 = plVar13 + 2;
  } while (plVar13 != (long *)&_end);
  __printf_chk(1,&DAT_00102130,iVar12);
  puts("\x1b[38;5;120m1) open page    - start a fresh story page\x1b[0m");
  puts("\x1b[38;5;120m2) paint page   - pour ink onto a page\x1b[0m");
  puts("\x1b[38;5;120m3) peek page    - read what the page remembers\x1b[0m");
  puts("\x1b[38;5;120m4) tear page    - rip a page from the book\x1b[0m");
  puts("\x1b[38;5;120m5) stitch pages - sew two pages into one tale\x1b[0m");
  puts("\x1b[38;5;120m6) whisper path - retie where a page points\x1b[0m");
  puts("\x1b[38;5;120m7) moon bell    - ring the workshop bell\x1b[0m");
  puts("\x1b[38;5;120m8) goodnight    - close the storybook\x1b[0m");
  puts("> ");
  uVar6 = get_num();
  switch(uVar6) {
  default:
    puts("?");
    goto LAB_00101268;
  case 1:
    puts("page id:");
    uVar3 = get_num();
    if (uVar3 < 0xc) {
      if ((&vats)[(long)(int)uVar3 * 2] == 0) {
        puts("page size:");
        sVar11 = get_num();
        if (sVar11 - 0x80 < 0x4a1) {
          pvVar9 = malloc(sVar11);
          (&vats)[(long)(int)uVar3 * 2] = pvVar9;
          if (pvVar9 == (void *)0x0) goto LAB_00101698;
          *(size_t *)(&DAT_00104068 + (long)(int)uVar3 * 0x10) = sVar11;
          puts("ok");
          goto LAB_00101268;
        }
      }
    }
    break;
  case 2:
    puts("page id:");
    uVar3 = get_num();
    if (uVar3 < 0xc) {
      if ((&vats)[(long)(int)uVar3 * 2] != 0) {
        puts("ink bytes:");
        uVar8 = get_num();
        if (uVar8 <= *(long *)(&DAT_00104068 + (long)(int)uVar3 * 0x10) + 0x80U) {
          puts("ink:");
          lVar15 = (&vats)[(long)(int)uVar3 * 2];
          uVar14 = 0;
          if (uVar8 != 0) {
            do {
              sVar7 = read(0,(void *)(lVar15 + uVar14),uVar8 - uVar14);
              if (sVar7 < 1) goto switchD_00101365_caseD_8;
              uVar14 = uVar14 + sVar7;
            } while (uVar14 < uVar8);
          }
          goto LAB_00101421;
        }
      }
    }
    break;
  case 3:
    puts("page id:");
    uVar3 = get_num();
    if (uVar3 < 0xc) {
      if ((&vats)[(long)(int)uVar3 * 2] != 0) {
        puts("peek bytes:");
        uVar8 = get_num();
        if (uVar8 <= *(long *)(&DAT_00104068 + (long)(int)uVar3 * 0x10) + 0x80U) {
          write(1,(void *)(&vats)[(long)(int)uVar3 * 2],uVar8);
          puts("");
          goto LAB_00101268;
        }
      }
    }
    break;
  case 4:
    puts("page id:");
    uVar3 = get_num();
    if ((uVar3 < 0xc) && ((void *)(&vats)[(long)(int)uVar3 * 2] != (void *)0x0)) {
      free((void *)(&vats)[(long)(int)uVar3 * 2]);
      puts("ok");
      goto LAB_00101268;
    }
    break;
  case 5:
    puts("first page:");
    uVar3 = get_num();
    puts("second page:");
    uVar4 = get_num();
    if ((uVar4 < 0xc) && (uVar3 < 0xc)) {
      lVar15 = (long)(int)uVar3 * 0x10;
      pvVar9 = (void *)(&vats)[(long)(int)uVar3 * 2];
      if ((pvVar9 != (void *)0x0) && ((&vats)[(long)(int)uVar4 * 2] != 0)) {
        lVar1 = *(long *)(&DAT_00104068 + lVar15);
        sVar11 = lVar1 + 0x20;
        pvVar9 = realloc(pvVar9,sVar11);
        if (pvVar9 == (void *)0x0) {
LAB_00101698:
                    /* WARNING: Subroutine does not return */
          exit(1);
        }
        (&vats)[(long)(int)uVar3 * 2] = pvVar9;
        puVar10 = (undefined8 *)((long)pvVar9 + lVar1);
        puVar2 = (undefined8 *)(&vats)[(long)(int)uVar4 * 2];
        uVar6 = puVar2[1];
        *puVar10 = *puVar2;
        puVar10[1] = uVar6;
        uVar6 = puVar2[3];
        puVar10[2] = puVar2[2];
        puVar10[3] = uVar6;
        *(size_t *)(&DAT_00104068 + lVar15) = sVar11;
        puts("ok");
      }
    }
    goto LAB_00101268;
  case 6:
    puts("page id:");
    uVar3 = get_num();
    if ((0xb < uVar3) || ((&vats)[(long)(int)uVar3 * 2] == 0)) break;
    puts("star token:");
    uVar8 = get_num();
    (&vats)[(long)(int)uVar3 * 2] = uVar8 ^ 0x51f0d1ce6e5b7a91;
    puts("ok");
    goto LAB_00101268;
  case 7:
    _IO_wfile_overflow(stderr,0x58);
LAB_00101421:
    puts("ok");
    goto LAB_00101268;
  case 8:
    goto switchD_00101365_caseD_8;
  }
  puts("no");
  goto LAB_00101268;
switchD_00101365_caseD_8:
                    /* WARNING: Subroutine does not return */
  exit(0);
}



//==================================================
// Function: _start at 001016b0
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
// Function: deregister_tm_clones at 001016e0
//==================================================

/* WARNING: Removing unreachable block (ram,0x001016f3) */
/* WARNING: Removing unreachable block (ram,0x001016ff) */

void deregister_tm_clones(void)

{
  return;
}



//==================================================
// Function: register_tm_clones at 00101710
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101734) */
/* WARNING: Removing unreachable block (ram,0x00101740) */

void register_tm_clones(void)

{
  return;
}



//==================================================
// Function: __do_global_dtors_aux at 00101750
//==================================================

void __do_global_dtors_aux(void)

{
  if (completed_8061 == '\0') {
    if (PTR___cxa_finalize_00103ff8 != (undefined *)0x0) {
      FUN_00101100(__dso_handle);
    }
    deregister_tm_clones();
    completed_8061 = 1;
    return;
  }
  return;
}



//==================================================
// Function: get_num at 001017a0
//==================================================

void get_num(void)

{
  char *pcVar1;
  long in_FS_OFFSET;
  undefined1 local_58 [16];
  undefined1 local_48 [16];
  undefined1 local_38 [16];
  undefined1 local_28 [16];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_58 = (undefined1  [16])0x0;
  local_48 = (undefined1  [16])0x0;
  local_38 = (undefined1  [16])0x0;
  local_28 = (undefined1  [16])0x0;
  pcVar1 = fgets(local_58,0x40,stdin);
  if (pcVar1 == (char *)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  strtol(local_58,(char **)0x0,10);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}



//==================================================
// Function: __libc_csu_init at 00101820
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
// Function: __libc_csu_fini at 00101890
//==================================================

void __libc_csu_fini(void)

{
  return;
}



//==================================================
// Function: _fini at 00101898
//==================================================

void _fini(void)

{
  return;
}


