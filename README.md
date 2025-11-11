## Bobx VeryHard 99% you can't do it | Crackme

В общем, вышло интересно. Рассказываю вкратце что я сделал
(этот текст писал не ии, лично мой труд, так что нажмите звездочку 🙏)

Сегодня нашел интерестный крякмис на crackmes.one в сложности 4, и меня забайтил заголовок "VeryHard 99% you can't do it", решил просмотреть он там делает, как загрузил бинарник сначала в **DIE** (detect it easy) и ничего особо не было, а в **IDA** увидел какую то кашу как это часто бывает (всякие функции бессмысленные, проверки, компиляторные хрени всякие), сразу пошел в вкладку Strings, там через xrefs перешел в функцию sub_140003530, и в ней уже вся начинка, по сути просто функция main, ее логика довольно **простая** и она **не обфусцирована** и **не запутана**, так что понять что где и как делает было нетрудно. Так же я ее декомпильнул, почистил код и ~примерные сурсы этой программы вы можете найти в папке `pseudo_source`

---

`````c
__int64 __fastcall typo_main()
{
  char v7; // bl
  char *getenvbobx; // rax
  int v9; // ebx
  int v10; // eax
  FILE *v11; // rax
  unsigned int v12; // eax
  unsigned int v13; // ebx
  int v14; // eax
  DWORD TickCount; // [rsp+5Ch] [rbp-14Ch] BYREF
  __m256 v18; // [rsp+60h] [rbp-148h]
  char Buffer[4]; // [rsp+80h] [rbp-128h] BYREF
  __int16 v20; // [rsp+84h] [rbp-124h]
  __int64 v21; // [rsp+188h] [rbp-20h]

  sth_xueta();
  __asm
  {
    vmovq   xmm2, cs:off_1400054A0; "Respect, Bobx!"
    vmovq   xmm3, cs:off_1400054A8; "Shoutout to Bobx!"
  }
  v21 = stack_canary;
  __asm { vpinsrq xmm1, xmm2, rax, 1 }
  __asm
  {
    vpinsrq xmm0, xmm3, rax, 1
    vinserti128 ymm0, ymm0, xmm1, 1
    vmovdqu [rsp+1A8h+var_178], ymm0
    vzeroupper
  }
  CreateThread(0, 0, StartAddress, 0, 0, 0);
  SetConsoleTitleA("Secure Authentication System v3.0 ULTRA");
  putchar(10);
  puts("===============================================");
  puts("    SECURE CRACKME CHALLENGE - ULTRA HARD");
  puts("    BY BOBX");
  puts("===============================================");
  putchar(10);
  __asm
  {
    vmovdqu ymm0, [rsp+1A8h+var_178]
    vmovdqu [rsp+1A8h+var_148], ymm0
    vzeroupper
  }
  TickCount = GetTickCount();
  srand(&TickCount ^ TickCount);
  v7 = rand();
  getenvbobx = getenv("BOBX");
  if ( getenvbobx && *getenvbobx )
  {
    printf(
      "\n%s\n",
      "BBBB   OOO   BBBB   XX  XX\n"
      "B   B O   O  B   B   XXXX \n"
      "BBBB  O   O  BBBB     XX  \n"
      "B   B O   O  B   B   XXXX \n"
      "BBBB   OOO   BBBB   XX  XX\n");
    printf("[egg] %s\n\n", *&v18.m256_f32[2 * (v7 & 3)]);
  }
  else if ( (-1431655765 * rand() + 715827882) <= 0x55555554 )
  {
    printf("\n[hint] %s (set BOBX=1 for full ASCII art)\n\n", *&v18.m256_f32[2 * (v7 & 3)]);
  }
  v9 = 5;
  do
  {
    security_checks();
    if ( v10 )
    {
      puts("[!] Security violation detected!");
      puts("[!] Terminating...");
      Sleep(0x3E8u);
      if ( v21 != stack_canary )
      {
        goto LABEL_24;
      }
LABEL_22:
      ExitProcess(1u);
    }
    Sleep(0x32u);
    --v9;
  }
  while ( v9 );
  puts("[*] Security checks passed.");
  puts("[*] System integrity verified.");
  putchar(10);
  printf("[*] Enter password (or type 'about'): ");
  v11 = __acrt_iob_func(0);
  if ( !fgets(Buffer, 256, v11) )
  {
    v13 = 1;
    puts("[!] Input error.");
    goto LABEL_14;
  }
  Buffer[strcspn(Buffer, "\n")] = 0;
  if ( *Buffer == 1970233953 && v20 == 116 )
  {
    puts("\n[about] Build: ultra-secure demo. Credits: Bobx.");
    puts("[about] Tip: set BOBX=1 before launch.\n");
  }
  security_checks();
  v13 = v12;
  if ( v12 )
  {
    puts("[!] Tampering detected!");
    if ( v21 != stack_canary )
    {
      goto LABEL_24;
    }
    goto LABEL_22;
  }
  check_pas(Buffer);
  if ( v14 )
  {
    putchar(10);
    puts("===============================================");
    puts("    [SUCCESS] Access Granted!");
    puts("    Flag: FLAG{U_CR4CK3D_TH3_ULT1M4TE_CH4LL3NG3}");
    puts("    Congratulations, elite hacker!");
    puts("===============================================");
  }
  else
  {
    putchar(10);
    puts("[!] Invalid password. Access denied.");
    puts("[!] Nice try, keep going!");
  }
  putchar(10);
  puts("Press ENTER to exit...");
  getchar();
LABEL_14:
  if ( v21 != stack_canary )
  {
LABEL_24:
    sub_140002560();
    JUMPOUT(0x1400038C4LL);
  }
  return v13;
}
`````
---

если мы чекнем механизм проверки пароля, то он достаточно простой, в данном примере, это посимвольная проверка пароля, а сама генерация пароля
будет немного дальше..

---
`````c
void __fastcall check_pas(char *Str)
{
  size_t v2; // rsi
  size_t v3; // rax
  bool v4; // zf
  char *v5; // rdx
  __int64 v6; // rax
  char v7; // cl
  int v8; // eax
  char Stra[72]; // [rsp+30h] [rbp-68h] BYREF
  __int64 v10; // [rsp+78h] [rbp-20h]

  v10 = stack_canary;
  sub_1400032E0(Stra); // <- вот тут находится сама генерация пароля, такая темка короче
  v2 = strlen(Stra);
  v3 = strlen(Str);
  if ( v3 == v2 )
  {
    v4 = v3 == 0;
    v5 = Stra;
    v6 = 0;
    v7 = 1;
    if ( !v4 )
    {
      do
      {
        v4 = Str[v6++] == *v5++;
        v7 &= v4;
      }
      while ( v2 != v6 );
    }
  }
  else
  {
    v8 = 0;
    if ( v2 )
    {
      do
      {
        v8 += 2;
      }
      while ( v8 != 2 * v2 );
    }
  }
  if ( v10 != stack_canary )
  {
    sub_140002560();
    JUMPOUT(0x1400034F9LL);
  }
}
`````
---

а дальше уже идет сам механизм генерации пароля, вообще он прост потому что визуально запутан, но на деле все очень просто (тут будет детальное объяснение)

---
`````c
__int64 __fastcall sub_1400032E0(char *Destination) // <- собственно сама функция, если упрощать то long long pass(char *d)
{
  char CurrentProcessId; // si
  char TickCount; // al
  __m256 *v8; // rdx
  __m256 *v9; // rcx
  char v10; // r8
  char v11; // al
  char v12; // al
  __int64 result; // rax
  __m256 v14; // [rsp+20h] [rbp-68h] BYREF
  __int64 v16; // [rsp+68h] [rbp-20h]

  __asm { vpxor   xmm0, xmm0, xmm0 } // <- асемблерные вставки от компилятора (оптимизация), зануляет 128 битный регистрЫ

  v16 = stack_canary; <- защита стека типо

  __asm { vmovdqu [rsp+88h+var_68], ymm0 } // <- зануляем стек через 256 битный регистр

  // <- xor нутый пароль по частям
  *&v14.m256_f32[6] = _RT0.m256i_i64[3];
  *v14.m256_f32 = 0x8783445371865073uLL;
  *&v14.m256_f32[2] = 0x484C8677454D4C85LL;
  *&v14.m256_f32[4] = 0x8280825F4C745086uLL;
  LOWORD(v14.m256_f32[6]) = -32378;
  BYTE2(v14.m256_f32[6]) = 33;

  __asm { vmovdqu [rsp+88h+var_48], ymm0
  vzeroupper } // <- дополнительно чистим стек + чистим верхние avx регистры 
  CurrentProcessId = GetCurrentProcessId();
  TickCount = GetTickCount();

  v8 = &v14;
  v9 = &v14;
  v10 = TickCount ^ CurrentProcessId; // <- вычисляем XOR ключ (кажется рандомным но на самом деле нет, смотрите ниже)
  v11 = 115;

  // первый проход: XOR строкипобайтово (визуально запутанно, по сути просто обходит массив)
  do
  {
    v9 = (v9 + 1);
    HIBYTE(v9[-1].m256_f32[7]) = v10 ^ v11; // <- применяем XOR к каждому байту
    v11 = LOBYTE(v9->m256_f32[0]);
  }
  while ( LOBYTE(v9->m256_f32[0]) ); // <- пока не встретим 0 терминатор (конец C строки)

  // второй проход: повторный XOR той же строки (по сути возвращаем строку к первозданному виду)
  v12 = LOBYTE(v14.m256_f32[0]);
  if ( LOBYTE(v14.m256_f32[0]) )
  {
    do
    {
      v8 = (v8 + 1);
      HIBYTE(v8[-1].m256_f32[7]) = v10 ^ v12;
      v12 = LOBYTE(v8->m256_f32[0]);
    }
    while ( LOBYTE(v8->m256_f32[0]) );
  }

  strcpy(Destination, &v14); // <- копируем копируем пароль
  result = v16 - stack_canary;
  if ( v16 != stack_canary ) // <- чекаем стек, если несовпадает то надпись будет "stack smashing detected"
  {
    sub_140002560();
    JUMPOUT(0x1400033DCLL);
  }
  return result; // <- возвращаем 0, значит что стек не поврежден
}
`````

---

### ИТОГ
Че можно сказать под итог про этот крякми? Неплохой, но мне кажется автор слишком сильно углубился в защиту от динамического анализа, хотя 
тут даже программу не надо запускать что бы решить ее.
Вообще решение этой задачи заняло у меня около 3 часов (отвлекался на разное, то поесть пойти, то че то пойду посмотрю на ютубе, в общем такое себе, ну а чистое решение этого crackme заняло бы ~1 час).
Что я мог бы посоветовать автору, это научиться делать xor обфускацию строк простую, и делать хотя бы простую защиту от статического анализа.

В общем спасибо `Bobx` за такую задачу, было прикольно порешать.

### Контакты
tg: ansarx_dev
