
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
  (*(code *)PTR_00103f70)();
  return;
}



//==================================================
// Function: _start at 001010f0
//==================================================

void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00103fd0)(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



//==================================================
// Function: FUN_00101120 at 00101120
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101133) */
/* WARNING: Removing unreachable block (ram,0x0010113f) */

void FUN_00101120(void)

{
  return;
}



//==================================================
// Function: FUN_00101150 at 00101150
//==================================================

/* WARNING: Removing unreachable block (ram,0x00101174) */
/* WARNING: Removing unreachable block (ram,0x00101180) */

void FUN_00101150(void)

{
  return;
}



//==================================================
// Function: _FINI_0 at 00101190
//==================================================

void _FINI_0(void)

{
  if (DAT_00104048 == '\0') {
    if (PTR___cxa_finalize_00103ff8 != (undefined *)0x0) {
      (*(code *)PTR___cxa_finalize_00103ff8)(__dso_handle);
    }
    FUN_00101120();
    DAT_00104048 = 1;
    return;
  }
  return;
}



//==================================================
// Function: setup at 001011e9
//==================================================

void setup(void)

{
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  f = fopen("./commands","r");
  return;
}



//==================================================
// Function: bit_flip at 0010124c
//==================================================

void bit_flip(void)

{
  long in_FS_OFFSET;
  int local_1c;
  byte *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (lock != -1) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  local_18 = (byte *)0x0;
  local_1c = 0;
  printf("> ");
  __isoc23_scanf(&DAT_00102018,&local_18);
  __isoc23_scanf(&DAT_0010201d,&local_1c);
  if ((local_1c < 8) && (-1 < local_1c)) {
    *local_18 = *local_18 ^ (byte)(1 << ((byte)local_1c & 0x1f));
  }
  else {
    puts("Go back to school");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: vuln at 0010132f
//==================================================

void vuln(void)

{
  void *pvVar1;
  long in_FS_OFFSET;
  int local_1c;
  undefined8 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = 0;
  printf("&main = %p\n",main);
  printf("&system = %p\n",PTR_system_00103fe0);
  printf("&address = %p\n",&local_18);
  pvVar1 = sbrk(0);
  printf("sbrk(NULL) = %p\n",pvVar1);
  for (local_1c = 0; local_1c < 3; local_1c = local_1c + 1) {
    bit_flip();
  }
  lock = 0;
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: main at 00101405
//==================================================

undefined8 main(void)

{
  setup();
  puts("I\'m feeling super generous today");
  vuln();
  return 0;
}



//==================================================
// Function: cmd at 00101429
//==================================================

void cmd(void)

{
  int iVar1;
  size_t sVar2;
  char *pcVar3;
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  do {
    pcVar3 = fgets(local_28,0x18,f);
    if (pcVar3 == (char *)0x0) {
      if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
        return;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    sVar2 = strcspn(local_28,"\n");
    local_28[sVar2] = '\0';
  } while ((local_28[0] == '\0') || (iVar1 = system(local_28), iVar1 != -1));
  perror("system");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}



//==================================================
// Function: _fini at 001014cc
//==================================================

void _fini(void)

{
  return;
}


