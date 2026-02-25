
//==================================================
// Function: _init at 00101000
//==================================================

void _init(void)

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
  (*(code *)PTR_00103f68)();
  return;
}



//==================================================
// Function: _start at 00101100
//==================================================

void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00103fd8)(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



//==================================================
// Function: deregister_tm_clones at 00101130
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101143) */
/* WARNING: Removing unreachable block (ram,0x0010114f) */

void deregister_tm_clones(void)

{
  return;
}



//==================================================
// Function: register_tm_clones at 00101160
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101184) */
/* WARNING: Removing unreachable block (ram,0x00101190) */

void register_tm_clones(void)

{
  return;
}



//==================================================
// Function: __do_global_dtors_aux at 001011a0
//==================================================

void __do_global_dtors_aux(void)

{
  if (completed_0 == '\0') {
    if (PTR___cxa_finalize_00103ff8 != (undefined *)0x0) {
      (*(code *)PTR___cxa_finalize_00103ff8)(__dso_handle);
    }
    deregister_tm_clones();
    completed_0 = 1;
    return;
  }
  return;
}



//==================================================
// Function: init_seccomp at 001011f9
//==================================================

void init_seccomp(void)

{
  long lVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  uVar2 = seccomp_init(0);
  seccomp_rule_add(uVar2,0x7fff0000,2,0);
  seccomp_rule_add(uVar2,0x7fff0000,0x101,0);
  seccomp_rule_add(uVar2,0x7fff0000,0,0);
  seccomp_rule_add(uVar2,0x7fff0000,1,0);
  seccomp_rule_add(uVar2,0x7fff0000,3,0);
  seccomp_rule_add(uVar2,0x7fff0000,0x3c,0);
  seccomp_rule_add(uVar2,0x7fff0000,0xe7,0);
  seccomp_rule_add(uVar2,0x7fff0000,5,0);
  seccomp_rule_add(uVar2,0x7fff0000,9,0);
  seccomp_rule_add(uVar2,0x7fff0000,10,0);
  seccomp_rule_add(uVar2,0x7fff0000,0xc,0);
  seccomp_load(uVar2);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: init at 001013a1
//==================================================

int init(EVP_PKEY_CTX *ctx)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  init_seccomp();
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}



//==================================================
// Function: get_int at 0010142e
//==================================================

void get_int(void)

{
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  read(0,local_28,0xf);
  atoi(local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: create_note at 0010147d
//==================================================

void create_note(void)

{
  long lVar1;
  int iVar2;
  int iVar3;
  void *pvVar4;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Index: ");
  iVar2 = get_int();
  if (((-1 < iVar2) && (iVar2 < 0x10)) && (*(long *)(notes + (long)iVar2 * 8) == 0)) {
    printf("Size: ");
    iVar3 = get_int();
    if ((0 < iVar3) && (iVar3 < 0x501)) {
      pvVar4 = malloc((long)iVar3);
      *(void **)(notes + (long)iVar2 * 8) = pvVar4;
      *(int *)(sizes + (long)iVar2 * 4) = iVar3;
      printf("Data: ");
      read(0,*(void **)(notes + (long)iVar2 * 8),(long)iVar3);
      puts("Created!");
    }
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}



//==================================================
// Function: delete_note at 001015c4
//==================================================

void delete_note(void)

{
  long lVar1;
  int iVar2;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Index: ");
  iVar2 = get_int();
  if (((-1 < iVar2) && (iVar2 < 0x10)) && (*(long *)(notes + (long)iVar2 * 8) != 0)) {
    free(*(void **)(notes + (long)iVar2 * 8));
    *(undefined8 *)(notes + (long)iVar2 * 8) = 0;
    *(undefined4 *)(sizes + (long)iVar2 * 4) = 0;
    puts("Deleted!");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: read_note at 001016a7
//==================================================

void read_note(void)

{
  long lVar1;
  int iVar2;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Index: ");
  iVar2 = get_int();
  if (((-1 < iVar2) && (iVar2 < 0x10)) && (*(long *)(notes + (long)iVar2 * 8) != 0)) {
    printf("Data: ");
    write(1,*(void **)(notes + (long)iVar2 * 8),(long)*(int *)(sizes + (long)iVar2 * 4));
    puts("");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: edit_note at 00101786
//==================================================

void edit_note(void)

{
  long lVar1;
  int iVar2;
  ssize_t sVar3;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Index: ");
  iVar2 = get_int();
  if (((-1 < iVar2) && (iVar2 < 0x10)) && (*(long *)(notes + (long)iVar2 * 8) != 0)) {
    printf("Data: ");
    sVar3 = read(0,*(void **)(notes + (long)iVar2 * 8),(long)*(int *)(sizes + (long)iVar2 * 4));
    if (-1 < (int)sVar3) {
      *(undefined1 *)((long)(int)sVar3 + *(long *)(notes + (long)iVar2 * 8)) = 0;
    }
    puts("Updated!");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: menu at 00101895
//==================================================

void menu(void)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puts("1. Create");
  puts("2. Delete");
  puts("3. Read");
  puts("4. Edit");
  puts("5. Exit");
  printf("> ");
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: main at 00101922
//==================================================

void main(EVP_PKEY_CTX *param_1)

{
  int iVar1;
  
  init(param_1);
  while( true ) {
    menu();
    iVar1 = get_int();
    if (iVar1 == 5) break;
    if (iVar1 < 6) {
      if (iVar1 == 4) {
        edit_note();
      }
      else if (iVar1 < 5) {
        if (iVar1 == 3) {
          read_note();
        }
        else if (iVar1 < 4) {
          if (iVar1 == 1) {
            create_note();
          }
          else if (iVar1 == 2) {
            delete_note();
          }
        }
      }
    }
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}



//==================================================
// Function: _fini at 0010199c
//==================================================

void _fini(void)

{
  return;
}


