
//==================================================
// Function: _init at 00100850
//==================================================

int _init(EVP_PKEY_CTX *ctx)

{
  undefined *puVar1;
  
  puVar1 = PTR___gmon_start___00301fe8;
  if (PTR___gmon_start___00301fe8 != (undefined *)0x0) {
    puVar1 = (undefined *)(*(code *)PTR___gmon_start___00301fe8)();
  }
  return (int)puVar1;
}



//==================================================
// Function: FUN_00100870 at 00100870
//==================================================

void FUN_00100870(void)

{
  (*(code *)PTR_00301f68)();
  return;
}



//==================================================
// Function: _start at 00100960
//==================================================

void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  (*(code *)PTR___libc_start_main_00301fe0)
            (main,param_2,&stack0x00000008,__libc_csu_init,__libc_csu_fini,param_1,auStack_8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}



//==================================================
// Function: deregister_tm_clones at 00100990
//==================================================

/* WARNING: Removing unreachable block (ram,0x001009a7) */
/* WARNING: Removing unreachable block (ram,0x001009b3) */

void deregister_tm_clones(void)

{
  return;
}



//==================================================
// Function: register_tm_clones at 001009d0
//==================================================

/* WARNING: Removing unreachable block (ram,0x001009f8) */
/* WARNING: Removing unreachable block (ram,0x00100a04) */

void register_tm_clones(void)

{
  return;
}



//==================================================
// Function: __do_global_dtors_aux at 00100a20
//==================================================

void __do_global_dtors_aux(void)

{
  if (completed_7698 == '\0') {
    if (PTR___cxa_finalize_00301ff8 != (undefined *)0x0) {
      __cxa_finalize(__dso_handle);
    }
    deregister_tm_clones();
    completed_7698 = 1;
    return;
  }
  return;
}



//==================================================
// Function: frame_dummy at 00100a60
//==================================================

void frame_dummy(void)

{
  register_tm_clones();
  return;
}



//==================================================
// Function: scanf_consume_newline at 00100a6a
//==================================================

undefined4 scanf_consume_newline(undefined8 param_1,undefined8 param_2)

{
  undefined4 uVar1;
  
  uVar1 = __isoc99_scanf(param_1,param_2);
  getchar();
  return uVar1;
}



//==================================================
// Function: pound at 00100a9f
//==================================================

void pound(void)

{
  int iVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  int local_20;
  uint local_1c;
  char *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_20 = 0;
  local_1c = 0;
  while (local_20 != -1) {
    puts("\nWelcome to the pound!");
    puts("1) Breed dog");
    puts("2) Release dog");
    puts("3) Leave");
    printf("> ");
    iVar1 = scanf_consume_newline(&DAT_001017b7,&local_20);
    if (iVar1 == 1) {
      if (local_20 == 2) {
        puts("Which dog do you want to release?");
        printf("Kennel Index > ");
        iVar1 = scanf_consume_newline(&DAT_001017b7,&local_1c);
        if (((iVar1 == 1) && (-1 < (int)local_1c)) && ((int)local_1c < 3)) {
          if (*(long *)(dogs + (long)(int)local_1c * 8) == 0) {
            puts("That kennel is empty!");
          }
          else {
            free(*(void **)(dogs + (long)(int)local_1c * 8));
            *(undefined8 *)(dogs + (long)(int)local_1c * 8) = 0;
            numOfDogs = numOfDogs + -1;
          }
        }
        else {
          puts("Invalid kennel");
        }
      }
      else if (local_20 == 3) {
        local_20 = -1;
      }
      else if (local_20 == 1) {
        puts("Select a kennel");
        printf("Kennel Index > ");
        iVar1 = scanf_consume_newline(&DAT_001017b7,&local_1c);
        if (((iVar1 == 1) && (-1 < (int)local_1c)) && ((int)local_1c < 3)) {
          if (*(long *)(dogs + (long)(int)local_1c * 8) == 0) {
            local_18 = (char *)malloc(0x28);
            puts("What is the dog\'s name?");
            printf("(Max 32 characters) > ");
            fgets(local_18 + 8,0x20,stdin);
            sVar2 = strcspn(local_18 + 8,"\n");
            local_18[sVar2 + 8] = '\0';
            local_18[0x28] = '\0';
            puts("How would you describe their speed?");
            printf("(Max 8 characters) > ");
            fgets(local_18,8,stdin);
            *(char **)(dogs + (long)(int)local_1c * 8) = local_18;
            printf("%s has been born into kennel %d!\n",local_18 + 8,(ulong)local_1c);
            numOfDogs = numOfDogs + 1;
          }
          else {
            printf("Kennel %d is occupied!\n",(ulong)local_1c);
          }
        }
        else {
          puts("Invalid kennel");
        }
      }
      else {
        puts("Invalid Option");
      }
    }
    else {
      puts("Not a number");
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}



//==================================================
// Function: hallOfFame at 00100ddf
//==================================================

void hallOfFame(void)

{
  undefined8 uVar1;
  int iVar2;
  char *pcVar3;
  long in_FS_OFFSET;
  int local_78;
  uint local_74;
  uint local_70;
  int local_6c;
  char *local_68;
  char *local_60;
  undefined8 local_58;
  long local_50;
  char local_48 [40];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_78 = 0;
  local_74 = 0;
  local_70 = 0;
LAB_001012d7:
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          if (local_78 == -1) {
            if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
              return;
            }
                    /* WARNING: Subroutine does not return */
            __stack_chk_fail();
          }
          puts("\nWelcome to the Hall of Fame!");
          puts("1) Read Record");
          puts("2) Wipe Record");
          puts("3) Leave");
          printf("> ");
          iVar2 = scanf_consume_newline(&DAT_001017b7,&local_78);
          if (iVar2 == 1) break;
          puts("Not a number");
        }
        if (local_78 != 2) break;
        puts("Select record to wipe");
        printf("Record index > ");
        iVar2 = scanf_consume_newline(&DAT_001017b7,&local_74);
        if (((iVar2 == 1) && (-1 < (int)local_74)) && ((int)local_74 < 0x10)) {
          if (*(long *)(winRecords + (long)(int)local_74 * 8) == 0) {
            printf("Record %d doesn\'t exist!\n",(ulong)local_74);
          }
          else {
            free(*(void **)(winRecords + (long)(int)local_74 * 8));
            *(undefined8 *)(winRecords + (long)(int)local_74 * 8) = 0;
            numOfRecords = numOfRecords + -1;
          }
        }
        else {
          puts("Invalid record");
        }
      }
      if (2 < local_78) break;
      if (local_78 == 1) {
        puts("Select a record");
        printf("Record index > ");
        iVar2 = scanf_consume_newline(&DAT_001017b7,&local_74);
        if (((iVar2 == 1) && (-1 < (int)local_74)) && ((int)local_74 < 0x10)) {
          if (*(long *)(winRecords + (long)(int)local_74 * 8) == 0) {
            printf("Record %d doesn\'t exist!\n",(ulong)local_74);
          }
          else {
            local_50 = *(long *)(winRecords + (long)(int)local_74 * 8);
            uVar1 = *(undefined8 *)(local_50 + 0x28);
            pcVar3 = ctime((time_t *)(local_50 + 0x20));
            printf("Dog: %s\n%s\nWins: %ld",local_50,pcVar3,uVar1);
            for (local_6c = 0; (ulong)(long)local_6c < *(ulong *)(local_50 + 0x28);
                local_6c = local_6c + 1) {
              printf("%d. %s\n",(ulong)(local_6c + 1),(long)local_6c * 0x18 + 0x30 + local_50);
            }
          }
        }
        else {
          puts("Invalid record");
        }
      }
      else {
LAB_001012cb:
        puts("Invalid Option");
      }
    }
    if (local_78 == 3) {
      local_78 = -1;
      goto LAB_001012d7;
    }
    if (local_78 != 4) goto LAB_001012cb;
    puts("CAUTION! FORGING RECORDS IS ILLEGAL");
    puts("Select a record");
    printf("Record index > ");
    iVar2 = scanf_consume_newline(&DAT_001017b7,&local_74);
    if (((iVar2 == 1) && (-1 < (int)local_74)) && ((int)local_74 < 0x10)) {
      if (*(long *)(winRecords + (long)(int)local_74 * 8) == 0) {
        printf("Record %d doesn\'t exist!\n",(ulong)local_74);
      }
      else {
        local_68 = *(char **)(winRecords + (long)(int)local_74 * 8);
        puts("Select a record to swap with");
        printf("Record Index > ");
        iVar2 = scanf_consume_newline(&DAT_001017b7,&local_70);
        if (((iVar2 == 1) && (-1 < (int)local_70)) && ((int)local_70 < 0x10)) {
          if (*(long *)(winRecords + (long)(int)local_70 * 8) == 0) {
            printf("Record %d doesn\'t exist!\n",(ulong)local_70);
          }
          else {
            local_60 = *(char **)(winRecords + (long)(int)local_70 * 8);
            local_48[0] = '\0';
            local_48[1] = '\0';
            local_48[2] = '\0';
            local_48[3] = '\0';
            local_48[4] = '\0';
            local_48[5] = '\0';
            local_48[6] = '\0';
            local_48[7] = '\0';
            local_48[8] = '\0';
            local_48[9] = '\0';
            local_48[10] = '\0';
            local_48[0xb] = '\0';
            local_48[0xc] = '\0';
            local_48[0xd] = '\0';
            local_48[0xe] = '\0';
            local_48[0xf] = '\0';
            local_48[0x10] = '\0';
            local_48[0x11] = '\0';
            local_48[0x12] = '\0';
            local_48[0x13] = '\0';
            local_48[0x14] = '\0';
            local_48[0x15] = '\0';
            local_48[0x16] = '\0';
            local_48[0x17] = '\0';
            local_48[0x18] = '\0';
            local_48[0x19] = '\0';
            local_48[0x1a] = '\0';
            local_48[0x1b] = '\0';
            local_48[0x1c] = '\0';
            local_48[0x1d] = '\0';
            local_48[0x1e] = '\0';
            local_48[0x1f] = '\0';
            local_58 = *(undefined8 *)(local_68 + 0x20);
            *(undefined8 *)(local_68 + 0x20) = *(undefined8 *)(local_60 + 0x20);
            *(undefined8 *)(local_60 + 0x20) = local_58;
            strcpy(local_48,local_68);
            strcpy(local_68,local_60);
            strcpy(local_60,local_48);
            printf("Record %d and %d have been swapped!\n",(ulong)local_74,(ulong)local_70);
          }
        }
        else {
          puts("Invalid record");
        }
      }
    }
    else {
      puts("Invalid record");
    }
  } while( true );
}



//==================================================
// Function: gameLoop at 001012ff
//==================================================

void gameLoop(void)

{
  int iVar1;
  time_t tVar2;
  long in_FS_OFFSET;
  int local_30;
  int local_2c;
  int local_28;
  uint local_24;
  ulong *local_20;
  void *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_30 = 0;
  local_2c = 0;
  puts("Welcome to the Dog Track!");
LAB_00101687:
  do {
    while( true ) {
      while( true ) {
        if (local_30 == -1) {
          if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
            return;
          }
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
        puts("\nSelect Option");
        puts("1) Go to pound");
        puts("2) Start race");
        puts("3) Hall of Fame");
        puts("4) Quit");
        printf("> ");
        iVar1 = scanf_consume_newline(&DAT_001017b7,&local_30);
        if (iVar1 == 1) break;
        puts("Not a number");
      }
      if (local_30 != 2) break;
      puts("Which dog do you want to race?");
      printf("Kennel Index > ");
      iVar1 = scanf_consume_newline(&DAT_001017b7,&local_2c);
      if (((iVar1 == 1) && (-1 < local_2c)) && (local_2c < 3)) {
        if (*(long *)(dogs + (long)local_2c * 8) == 0) {
          puts("That kennel is empty!");
        }
        else {
          local_20 = *(ulong **)(dogs + (long)local_2c * 8);
          local_18 = malloc(0xf0);
          local_28 = 0;
          while ((local_28 < 0x20 && (*(char *)((long)local_20 + (long)local_28 + 8) != '\0'))) {
            *(undefined1 *)((long)local_18 + (long)local_28) =
                 *(undefined1 *)((long)local_20 + (long)local_28 + 8);
            local_28 = local_28 + 1;
          }
          tVar2 = time((time_t *)0x0);
          *(time_t *)((long)local_18 + 0x20) = tVar2;
          *(undefined8 *)((long)local_18 + 0x28) = 0;
          for (local_24 = 0; (int)local_24 < 8; local_24 = local_24 + 1) {
            printf("\n%s now entering Race %d: %s!\n",local_20 + 1,(ulong)(local_24 + 1),
                   races + (long)(int)local_24 * 0x18);
            puts("3... 2... 1... Go!");
            if ((*local_20 & 0xff) <= (ulong)(long)(int)(local_24 << 5)) {
              printf("%s has lost...\n",local_20 + 1);
              printf("%s won %d races in this run!\n",local_20 + 1,(ulong)local_24);
              break;
            }
            printf("%s has won the race!\n",local_20 + 1);
            strcpy((char *)((long)local_18 + (long)(int)local_24 * 0x18 + 0x30),
                   races + (long)(int)local_24 * 0x18);
            *(long *)((long)local_18 + 0x28) = (long)(int)(local_24 + 1);
          }
          *(void **)(winRecords + (long)(numOfRecords % 0x10) * 8) = local_18;
          numOfRecords = numOfRecords + 1;
        }
      }
      else {
        puts("Invalid kennel");
      }
    }
    if (2 < local_30) {
      if (local_30 == 3) {
        hallOfFame();
      }
      else if (local_30 == 4) {
        local_30 = -1;
      }
      else {
LAB_0010167a:
        puts("Invalid Option");
      }
      goto LAB_00101687;
    }
    if (local_30 != 1) goto LAB_0010167a;
    pound();
  } while( true );
}



//==================================================
// Function: main at 001016aa
//==================================================

undefined8 main(void)

{
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  gameLoop();
  return 0;
}



//==================================================
// Function: __libc_csu_init at 001016f0
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
// Function: __libc_csu_fini at 00101760
//==================================================

void __libc_csu_fini(void)

{
  return;
}



//==================================================
// Function: _fini at 00101764
//==================================================

void _fini(void)

{
  return;
}


