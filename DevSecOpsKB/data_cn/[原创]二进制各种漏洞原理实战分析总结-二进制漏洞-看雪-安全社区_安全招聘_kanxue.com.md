[bbs.kanxue.com](https://bbs.kanxue.com/thread-252569.htm)
# \[原创\]二进制各种漏洞原理实战分析总结-二进制漏洞-看雪-安全社区|安全招聘|kanxue.com

XiunoBBS 4.0,

28 min read

---

<fieldset><legend>目录</legend>

* [0x01栈溢出漏洞原理](#0x01栈溢出漏洞原理)
* [0x02 堆溢出漏洞原理]()
* [0x03 堆调试技巧]()
* [堆尾检查](#堆尾检查)
* [页堆](#页堆)
* [0x04整数溢出漏洞原理](#0x04整数溢出漏洞原理)
* [基于栈的整数溢出](#基于栈的整数溢出)
* [基于堆的整数溢出](#基于堆的整数溢出)
* [0x05 格式化字符串漏洞原理]()
* [0x06 双重释放漏洞原理]()
* [0x07释放后重引用漏洞原理](#0x07释放后重引用漏洞原理)
* [0x08 数组越界访问漏洞]()
* [0x09类型混淆漏洞原理](#0x09类型混淆漏洞原理)
* [0x10竞争条件漏洞原理](#0x10竞争条件漏洞原理)
* [参考信息](#参考信息)</fieldset>

本部分将对常见的二进制漏洞做系统分析，方便在漏洞挖掘过程中定位识别是什么类型漏洞，工欲善其事，必先利其器。

栈溢出漏洞属于缓冲区漏洞的一种，实例如下：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15|`int` `main()`

`{`

`char``*``str` `=` `"AAAAAAAAAAAAAAAAAAAAAAAA"``;`

`vulnfun(``str``);`

`return``;`

`}`

`int` `vulnfun(char``*``str``)`

`{`

`char stack[``10``];`

`strcpy(stack,``str``);``/``/` `这里造成溢出！`

`}`|


编译后使用windbg运行

![](https://bbs.kanxue.com/upload/attach/201907/823237_F4PWZT2F7BS7UZ2.png)

直接运行到了地址0x41414141，这个就是字符串AAAA，就是变量str里面的字符串通过strcpy拷贝到栈空间时，没有对字符串长度做限制，导致了栈溢出，最后覆盖到了返回地址，造成程序崩溃。

溢出后的栈空间布局如下：

![](https://bbs.kanxue.com/upload/attach/201907/823237_FXWFF95ZPFEECE4.png)

栈溢出原理图

使用以下代码演示堆溢出漏洞

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21|`int` `main ( )`

`{`

`HANDLE hHeap;`

`char``*``heap;`

`char``str``[]``=` `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"``;`

`hHeap``=` `HeapCreate(HEAP_GENERATE_EXCEPTIONS,``0x1000``,``0xffff``);`

`getchar();``/``/` `用于暂停程序，便于调试器加载`

`heap``=` `HeapAlloc(hHeap,``0``,``0x10``);`

`printf(``"heap addr:0x%08x\n"``,heap);`

`strcpy(heap,``str``);``/``/` `导致堆溢出`

`HeapFree(hHeap,``0``, heap);``/``/` `触发崩溃`

`HeapDestroy(hHeap);`

`return` `0``;`

`}`|


由于调试堆和常态堆的结构不同，在演示代码中加入getchar函数，用于暂停进程，方便运行heapoverflowexe后用调试器附加进程。debug版本和Release版本实际运行的进程中各个内存结构和分配过程也不同，因此测试的时候应该编译成release版本。

运行程序，使用windbg附加调试（一定要附加调试），g运行后程序崩溃

![](https://bbs.kanxue.com/upload/attach/201907/823237_FYUAWTW38PV3MWA.png)

上面的ecx已经被AAAA字符串覆盖掉了，最后在引用该地址的时候导致崩溃，通过前面的栈回溯定位到了main函数入口，找到复制字符串的函数下断点

![](https://bbs.kanxue.com/upload/attach/201907/823237_TRUUHRA69MRMA7B.png)

此时堆块已经分配完毕，对应的分配地址位于0x007104a0，0x007104a0是堆块数据的起始地址，并非堆头信息的起始地址，对于已经分配的堆块，开头有8字节的HEAP\_ENTRY结构，因此heap的HEAP\_ENTRY结构位于0x007104a0-8=0x710498。

![](https://bbs.kanxue.com/upload/attach/201907/823237_6G2Y98UQQUXW3W4.png)

在windbg上查看两个堆块的信息，这两个堆块目前处于占用状态，共有0x10大小空间

|||
|---|---|
|1

2

3

4

5|`0``:``000``> !heap``-``p``-``a``0x710498`

`address``00710498` `found``in`

`_HEAP @``710000`

`HEAP_ENTRY Size Prev Flags UserPtr UserSize``-` `state`

`00710498` `0005` `0000` `[``00``]``007104a0` `00010` `-` `(busy)`|


在windbg中，使用！heap查看HeapCreate创建的整个堆块信息，可以发现堆块heap后面还有一个空闲堆块0x007104c0：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

24

25

26

27

28

29

30

31

32

33

34

35

36

37

38

39

40

41

42

43

44

45

46

47

48|`0``:``000``> !heap`

`Heap Address NT``/``Segment Heap`

`560000` `NT Heap`

`800000` `NT Heap`

`710000` `NT Heap`

`0``:``000``> !heap``-``a``710000`

`HEAPEXT: Unable to get address of ntdll!RtlpHeapInvalidBadAddress.`

`Index Address Name Debugging options enabled`

`3``:``00710000`

`Segment at``00710000` `to``00720000` `(``00001000` `bytes committed)`

`Flags:``40001064`

`ForceFlags:``40000064`

`Granularity:``8` `bytes`

`Segment Reserve:``00100000`

`Segment Commit:``00002000`

`DeCommit Block Thres:``00000200`

`DeCommit Total Thres:``00002000`

`Total Free Size:``00000164`

`Max``. Allocation Size:``7ffdefff`

`Lock Variable at:``00710248`

`Next` `TagIndex:``0000`

`Maximum TagIndex:``0000`

`Tag Entries:``00000000`

`PsuedoTag Entries:``00000000`

`Virtual Alloc``List``:``0071009c`

`Uncommitted ranges:``0071008c`

`00711000``:``0000f000` `(``61440` `bytes)`

`FreeList[``00` `] at``007100c0``:``007104c8` `.``007104c8`

`007104c0``:``00028` `.``00b20` `[``104``]``-` `free`

`Segment00 at``00710000``:`

`Flags:``00000000`

`Base:``00710000`

`First Entry:``00710498`

`Last Entry:``00720000`

`Total Pages:``00000010`

`Total UnCommit:``0000000f`

`Largest UnCommit:``00000000`

`UnCommitted Ranges: (``1``)`

`Heap entries``for` `Segment00``in` `Heap``00710000`

`address: psize . size flags state (requested size)`

`00710000``:``00000` `.``00498` `[``101``]``-` `busy (``497``)`

`00710498``:``00498` `.``00028` `[``107``]``-` `busy (``10``), tail fill``/``/``heap的占用堆块`

`007104c0``:``00028` `.``00b20` `[``104``] free fill``/``/``空闲堆块`

`00710fe0``:``00b20` `.``00020` `[``111``]``-` `busy (``1d``)`

`00711000``:``0000f000` `-` `uncommitted bytes.`|


在复制字符串的时候，原本只有0x10大小的堆块，填充过多的字符串的时候就会覆盖到下方的空闲堆块007104c0，在复制前007104c0空闲堆块的HEAP\_FREE\_ENTRY结构数据如下：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

24

25

26|`0``:``000``> dt _HEAP_FREE_ENTRY``0x007104c0`

`ntdll!_HEAP_FREE_ENTRY`

`+``0x000` `HeapEntry : _HEAP_ENTRY`

`+``0x000` `UnpackedEntry : _HEAP_UNPACKED_ENTRY`

`+``0x000` `Size :``0x6298`

`+``0x002` `Flags :``0x16` `''`

`+``0x003` `SmallTagIndex :``0xac` `''`

`+``0x000` `SubSegmentCode :``0xac166298`

`+``0x004` `PreviousSize :``0xcfb9`

`+``0x006` `SegmentOffset :``0` `''`

`+``0x006` `LFHFlags :``0` `''`

`+``0x007` `UnusedBytes :``0` `''`

`+``0x000` `ExtendedEntry : _HEAP_EXTENDED_ENTRY`

`+``0x000` `FunctionIndex :``0x6298`

`+``0x002` `ContextValue :``0xac16`

`+``0x000` `InterceptorValue :``0xac166298`

`+``0x004` `UnusedBytesLength :``0xcfb9`

`+``0x006` `EntryOffset :``0` `''`

`+``0x007` `ExtendedBlockSignature :``0` `''`

`+``0x000` `Code1 :``0xac166298`

`+``0x004` `Code2 :``0xcfb9`

`+``0x006` `Code3 :``0` `''`

`+``0x007` `Code4 :``0` `''`

`+``0x004` `Code234 :``0xcfb9`

`+``0x000` `AgregateCode :``0x0000cfb9``` `ac166298 ``

`+``0x008` `FreeList : _LIST_ENTRY [``0x7100c0` `-` `0x7100c0` `]`|

|||
|---|---|
|1

2

3

4

5|`0``:``000``> dt _LIST_ENTRY``0x007104c0``+``8`

`ntdll!_LIST_ENTRY`

`[``0x7100c0` `-` `0x7100c0` `]`

`+``0x000` `Flink :``0x007100c0` `_LIST_ENTRY [``0x7104c8` `-` `0x7104c8` `]`

`+``0x004` `Blink :``0x007100c0` `_LIST_ENTRY [``0x7104c8` `-` `0x7104c8` `]`|


覆盖后0x007104c0空闲块的HEAP\_FREE\_ENTRY结构数据如下：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

24

25

26

27

28

29

30

31

32

33

34|`0``:``000``> g`

`(``2c08``.``234``): Access violation``-` `code c0000005 (!!! second chance !!!)`

`eax``=``007e04a0` `ebx``=``007e0498` `ecx``=``41414141` `edx``=``007e0260` `esi``=``007e04b8` `edi``=``007e0000`

`eip``=``7775919d` `esp``=``0019fdb0` `ebp``=``0019fea8` `iopl``=``0` `nv up ei ng nz na po cy`

`cs``=``0023` `ss``=``002b` `ds``=``002b` `es``=``002b` `fs``=``0053` `gs``=``002b` `efl``=``00010283`

`ntdll!RtlpFreeHeap``+``0x5bd``:`

`7775919d` `8b11` `mov edx,dword ptr [ecx] ds:``002b``:``41414141``=``????????`

`0``:``000``> dt _HEAP_FREE_ENTRY``0x007104c0`

`ntdll!_HEAP_FREE_ENTRY`

`+``0x000` `HeapEntry : _HEAP_ENTRY`

`+``0x000` `UnpackedEntry : _HEAP_UNPACKED_ENTRY`

`+``0x000` `Size : ??`

`+``0x002` `Flags : ??`

`+``0x003` `SmallTagIndex : ??`

`+``0x000` `SubSegmentCode : ??`

`+``0x004` `PreviousSize : ??`

`+``0x006` `SegmentOffset : ??`

`+``0x006` `LFHFlags : ??`

`+``0x007` `UnusedBytes : ??`

`+``0x000` `ExtendedEntry : _HEAP_EXTENDED_ENTRY`

`+``0x000` `FunctionIndex : ??`

`+``0x002` `ContextValue : ??`

`+``0x000` `InterceptorValue : ??`

`+``0x004` `UnusedBytesLength : ??`

`+``0x006` `EntryOffset : ??`

`+``0x007` `ExtendedBlockSignature : ??`

`+``0x000` `Code1 : ??`

`+``0x004` `Code2 : ??`

`+``0x006` `Code3 : ??`

`+``0x007` `Code4 : ??`

`+``0x004` `Code234 : ??`

`+``0x000` `AgregateCode : ??`

`+``0x008` `FreeList : _LIST_ENTRY`

`Memory read error``007104c0`|


整个空闲堆头信息都被覆盖了，包括最后的空闲链表中的前后向指针都被成了0x41414141，后面调用HeapFree释放堆块的时候，就会将buf2和后面的空闲堆块0x007104c0合并，修改两个空闲堆块的前后向指针就会引用0x41414141，最后造成崩溃。

如果把上面释放堆块的操作换成分配堆块HeapAlloc（），也会导致崩溃，因为在分配堆块的时候会去遍历空闲链表指针，会造成地址引用异常，当内存中已经分配多个堆块的时候，可能覆盖到的就是已经分配到的堆块，此时可能就是覆盖HEAP\_ENTRY结构，而不是HEAP\_FREE\_ENTRY结构。

![](https://bbs.kanxue.com/upload/attach/201907/823237_7JVGRQPDWBKQ9P8.png)

堆溢出原理图

微软提供了一些调试选项用于辅助堆调试，可以通过windbg提供的gflag.exe或者！gflag命令来设置：

|||
|---|---|
|1

2

3

4

5

6|`htc：堆尾检查，是否发生溢出`

`hfc：堆释放检查`

`hpc：堆参数检查`

`hpa：启用页堆`

`htg：堆标志`

`ust：用户态栈回溯`|


对heapoverflow.exe添加堆尾检查和页堆，去掉堆标志：

|||
|---|---|
|1|`gflags.exe``-``i F:\vulns\Release\heapoverflow``+``htc``+``hpa``+``htg`|

#### 堆尾检查

主要是在每个堆块的尾部，用户数据之后添加8字节，通常是连续的2个0xabababab，该数据段被破坏就可能发生了溢出。

对heapoverflow.exe开启hpc和htc，用windbg加载对heapoverflow程序，附加进程无法在堆尾添加额外标志，使用以下命令开启堆尾检查和堆参数检查：

|||
|---|---|
|1

2

3

4

5|`0``:``000``> !gflag``+``htc``+``hpc`

`Current NtGlobalFlag contents:``0x00000070`

`htc``-` `Enable heap tail checking`

`hfc``-` `Enable heap free checking`

`hpc``-` `Enable heap parameter checking`|

|||
|---|---|
|1

2

3

4

5

6

7|`0``:``000``:x86> g`

`HEAP[heapoverflow.exe]: Heap block at``001E0498` `modified at``001E04B0` `past requested size of``10`

`(``13d0``.``3c9c``): WOW64 breakpoint``-` `code``4000001f` `(first chance)`

`First chance exceptions are reported before``any` `exception handling.`

`This exception may be expected``and` `handled.`

`ntdll_77710000!RtlpBreakPointHeap``+``0x13``:`

`777f07c7` `cc``int` `3`|


执行命令g后，按下回车键程序会断下来

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13|`0``:``000``:x86> kb`

`00` `0019fd18` `777dd85b` `00000000` `001e0000` `001e0498` `ntdll_77710000!RtlpBreakPointHeap``+``0x13`

`01` `0019fd30` `77793e9c` `001e0000` `00000000` `77786780` `ntdll_77710000!RtlpCheckBusyBlockTail``+``0x1a2`

`02` `0019fd4c` `777ef9f1` `7772e4dc` `9ceeef49` `001e0000` `ntdll_77710000!RtlpValidateHeapEntry``+``0x633d9`

`03` `0019fda4` `7775991d` `001e04a0` `9ceeec45` `001e0498` `ntdll_77710000!RtlDebugFreeHeap``+``0xbf`

`04` `0019fea8` `77758b98` `001e0498` `001e04a0` `001e04c1` `ntdll_77710000!RtlpFreeHeap``+``0xd3d`

`*``*``*` `WARNING: Unable to verify checksum``for` `F:\vulns\Release\heapoverflow.exe`

`05` `0019fefc` `00401094` `001e0000` `00000000` `001e04a0` `ntdll_77710000!RtlFreeHeap``+``0x758`

`WARNING: Stack unwind information``not` `available. Following frames may be wrong.`

`06` `001e0000` `01000709` `ffeeffee``00000000` `001e00a4` `heapoverflow``+``0x1094`

`07` `001e0004` `ffeeffee``00000000` `001e00a4` `001e00a4` `0x1000709`

`08` `001e0008` `00000000` `001e00a4` `001e00a4` `001e0000` `0xffeeffee`|

|||
|---|---|
|1|`HEAP[heapoverflow.exe]: Heap block at``001E0498` `modified at``001E04B0` `past requested size of``10`|


上面一句调试输出信息的意思是，在大小为0x10的堆块0x001E0498的0x001E04B0覆盖破坏了，0x10大小的空间加上堆头的8字节一共0x18字节，0x001E04B0-0x001E0498=0x18，也就是说0x001E04B0位于堆块数据的最后一个字节上，基于上面的信息，可以分析出程序主要是因为向0x10的堆块中复制过多数据导致的堆溢出。

#### 页堆

在调试漏洞的时候，经常需要定位导致漏洞的代码和函数，比如导致堆溢出的字节复制指令rep movsz等，前面的堆尾检查方式主要是堆被破坏的场景，不利于定位导致漏洞的代码。为此。引入了页堆的概念，开启后，会在堆块中增加不可访问的栅栏页，溢出覆盖到栅栏页就会触发异常。

开启页堆：

|||
|---|---|
|1|`gflags.exe``-``i F:\vulns\Release\heapoverflow``+``hpa`|


![](https://bbs.kanxue.com/upload/attach/201907/823237_JDMHTJ6E7VK7UPZ.png)

用windbg加载heapoverflow，运行！gflag命令开启了页堆，然后g运行后在cmd按下回车键断下

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

24

25|`0``:``000``> g`

`(``46c``.b74): Access violation``-` `code c0000005 (!!! second chance !!!)`

`eax``=``00000021` `ebx``=``01795ff0` `ecx``=``00000004` `edx``=``77d364f4` `esi``=``0012ff38` `edi``=``01796000`

`eip``=``00401084` `esp``=``0012ff10` `ebp``=``01790000` `iopl``=``0` `nv up ei pl nz na po nc`

`cs``=``001b` `ss``=``0023` `ds``=``0023` `es``=``0023` `fs``=``003b` `gs``=``0000` `efl``=``00010202`

`image00400000``+``0x1084``:`

`00401084` `f3a5 rep movs dword ptr es:[edi],dword ptr [esi]`

`0``:``000``> dd esi`

`0012ff38` `41414141` `41414141` `41414141` `41414141`

`0012ff48` `00407000` `00401327` `00000001` `01699fb0`

`0012ff58` `0169bf70` `00000000` `00000000` `7ffdd000`

`0012ff68` `c0000005``00000000` `0012ff5c` `0012fb1c`

`0012ff78` `0012ffc4` `00402c50` `004060b8` `00000000`

`0012ff88` `0012ff94` `76281174` `7ffdd000` `0012ffd4`

`0012ff98` `77d4b3f5` `7ffdd000` `77cb48a4` `00000000`

`0012ffa8` `00000000` `7ffdd000` `c0000005``76292b35`

`0``:``000``> dc edi`

`01796000` `???????? ???????? ???????? ???????? ????????????????`

`01796010` `???????? ???????? ???????? ???????? ????????????????`

`01796020` `???????? ???????? ???????? ???????? ????????????????`

`01796030` `???????? ???????? ???????? ???????? ????????????????`

`01796040` `???????? ???????? ???????? ???????? ????????????????`

`01796050` `???????? ???????? ???????? ???????? ????????????????`

`01796060` `???????? ???????? ???????? ???????? ????????????????`

`01796070` `???????? ???????? ???????? ???????? ????????????????`|


可以发现程序在复制A字符串的时候触发了异常，程序复制到0x11字节的时候被断下，此时异常还未破坏到堆块，直接定位导致溢出的复制指令rep movs

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19|`0``:``000``> kb`

`ChildEBP RetAddr Args to Child`

`WARNING: Stack unwind information``not` `available. Following frames may be wrong.`

`0012ff48` `00401327` `00000001` `01699fb0` `0169bf70` `image00400000``+``0x1084`

`*``*``*` `ERROR: Symbol``file` `could``not` `be found. Defaulted to export symbols``for` `C:\Windows\system32\kernel32.dll``-`

`0012ff88` `76281174` `7ffdd000` `0012ffd4` `77d4b3f5` `image00400000``+``0x1327`

`0012ff94` `77d4b3f5` `7ffdd000` `77cb48a4` `00000000` `kernel32!BaseThreadInitThunk``+``0x12`

`0012ffd4` `77d4b3c8` `0040b000` `7ffdd000` `00000000` `ntdll!RtlInitializeExceptionChain``+``0x63`

`0012ffec` `00000000` `0040b000` `7ffdd000` `00000000` `ntdll!RtlInitializeExceptionChain``+``0x36`

`0``:``000``> ub image00400000``+``0x1327`

`image00400000``+``0x1301``:`

`00401301` `e847120000 call image00400000``+``0x254d` `(``0040254d``)`

`00401306` `e8af0e0000 call image00400000``+``0x21ba` `(``004021ba``)`

`0040130b` `a150994000 mov eax,dword ptr [image00400000``+``0x9950` `(``00409950``)]`

`00401310` `a354994000 mov dword ptr [image00400000``+``0x9954` `(``00409954``)],eax`

`00401315` `50` `push eax`

`00401316` `ff3548994000 push dword ptr [image00400000``+``0x9948` `(``00409948``)]`

`0040131c` `ff3544994000 push dword ptr [image00400000``+``0x9944` `(``00409944``)]`

`00401322` `e8d9fcffff call image00400000``+``0x1000` `(``00401000``)`|


根据栈回溯，调用rep movs的上一层函数位于image00400000+0x1084的上一条指令，也就是00401322，此处调用了00401000函数，很容易发现这是主入口函数：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

24

25

26

27

28

29

30

31

32

33

34

35

36

37

38

39

40

41

42

43

44

45

46

47

48

49

50

51

52

53

54

55

56

57

58

59

60

61

62

63

64

65

66

67

68|`0``:``000``> uf``00401000`

`image00400000``+``0x1000``:`

`00401000` `83ec24` `sub esp,``24h`

`00401003` `b908000000 mov ecx,``8`

`00401008` `53` `push ebx`

`00401009` `55` `push ebp`

`0040100a` `56` `push esi`

`0040100b` `57` `push edi`

`0040100c` `be44704000 mov esi,offset image00400000``+``0x7044` `(``00407044``)`

`00401011` `8d7c2410` `lea edi,[esp``+``10h``]`

`00401015` `f3a5 rep movs dword ptr es:[edi],dword ptr [esi]`

`00401017` `68ffff0000` `push``0FFFFh`

`0040101c` `6800100000` `push``1000h` `/``/``堆块大小压入`

`00401021` `6a04` `push``4`

`00401023` `a4 movs byte ptr es:[edi],byte ptr [esi]`

`00401024` `ff150c604000 call dword ptr [image00400000``+``0x600c` `(``0040600c``)]``/``/``调用HeapCreate创建堆块`

`0040102a` `8be8` `mov ebp,eax`

`0040102c` `a16c704000 mov eax,dword ptr [image00400000``+``0x706c` `(``0040706c``)]`

`00401031` `48` `dec eax`

`00401032` `a36c704000 mov dword ptr [image00400000``+``0x706c` `(``0040706c``)],eax`

`00401037` `7808` `js image00400000``+``0x1041` `(``00401041``)`

`image00400000``+``0x1039``:`

`00401039` `ff0568704000 inc dword ptr [image00400000``+``0x7068` `(``00407068``)]`

`0040103f` `eb0d jmp image00400000``+``0x104e` `(``0040104e``)`

`image00400000``+``0x1041``:`

`00401041` `6868704000` `push offset image00400000``+``0x7068` `(``00407068``)`

`00401046` `e896000000 call image00400000``+``0x10e1` `(``004010e1``)`

`0040104b` `83c404` `add esp,``4`

`image00400000``+``0x104e``:`

`0040104e` `6a10` `push``10h`

`00401050` `6a00` `push``0`

`00401052` `55` `push ebp`

`00401053` `ff1508604000 call dword ptr [image00400000``+``0x6008` `(``00406008``)]``/``/``调用HeapAlloc分配``0x10``的堆块`

`00401059` `8bd8` `mov ebx,eax``/``/``分配的堆块地址`

`0040105b` `53` `push ebx`

`0040105c` `6830704000` `push offset image00400000``+``0x7030` `(``00407030``)`

`00401061` `e84a000000 call image00400000``+``0x10b0` `(``004010b0``)`

`00401066` `8d7c2418` `lea edi,[esp``+``18h``]`

`0040106a` `83c9ff` `or` `ecx,``0FFFFFFFFh`

`0040106d` `33c0` `xor eax,eax`

`0040106f` `83c408` `add esp,``8`

`00401072` `f2ae repne scas byte ptr es:[edi]`

`00401074` `f7d1``not` `ecx``/``/``获取``str``长度`

`00401076` `2bf9` `sub edi,ecx`

`00401078` `53` `push ebx`

`00401079` `8bc1` `mov eax,ecx`

`0040107b` `8bf7` `mov esi,edi``/``/``str` `=` `0x20`

`0040107d` `8bfb` `mov edi,ebx``/``/``分配的堆块只有``0x10`

`0040107f` `6a00` `push``0`

`00401081` `c1e902 shr ecx,``2`

`00401084` `f3a5 rep movs dword ptr es:[edi],dword ptr [esi]`

`00401086` `8bc8` `mov ecx,eax`

`00401088` `55` `push ebp`

`00401089` `83e103` `and` `ecx,``3`

`0040108c` `f3a4 rep movs byte ptr es:[edi],byte ptr [esi]``/``/``0x20` `<``0x10` `循环复制导致溢出`

`0040108e` `ff1504604000 call dword ptr [image00400000``+``0x6004` `(``00406004``)]`

`00401094` `55` `push ebp`

`00401095` `ff1500604000 call dword ptr [image00400000``+``0x6000` `(``00406000``)]`

`0040109b` `5f` `pop edi`

`0040109c` `5e` `pop esi`

`0040109d` `5d` `pop ebp`

`0040109e` `33c0` `xor eax,eax`

`004010a0` `5b` `pop ebx`

`004010a1` `83c424` `add esp,``24h`

`004010a4` `c3 ret`|


整数分为有符号和无符号两类，有符号数以最高位作为符号位，正整数最高位为1，负整数最高位为0，不同类型的整数在内存中有不同的取值范围，unsigned int = 4字节，int = 4字节，当存储的数值超过该类型整数的最大值就会发生溢出。

在一些有符号和无符号转换的过程中最有可能发生整数溢出漏洞。

![](https://bbs.kanxue.com/upload/attach/201907/823237_XXJ4WN4XMZJZW55.png)

![](https://bbs.kanxue.com/upload/attach/201907/823237_Z8U3BWFNKYR94WF.png)

#### 基于栈的整数溢出

基于栈的整数溢出的例子：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

24

25

26|`int` `main(``int` `argc, char``*``argv){`

`int` `i;`

`char buf[``8``];``/``/` `栈缓冲区`

`unsigned short``int` `size;``/``/` `无符号短整数取值范围：``0` `~``65535`

`char overflow[``65550``];`

`memset(overflow,``65``,sizeof(overflow));``/``/` `填充为“A”字符`

`printf(``"请输入数值:\n"``);`

`scanf(``"%d"``,&i);``/``/``输入``65540`

`size``=` `i;`

`printf(``"size：%d\n"``,size);``/``/` `输出系统识别出来的size数值``4`

`printf(``"i：%d\n"``,i);``/``/` `输出系统识别出来的i数据``65540`

`if` `(size >``8``)``/``/``边界检查`

`return` `-``1``;`

`memcpy(buf,overflow,i);``/``/` `栈溢出`

`return` `0``;`

`}`|


代码中size变量是无符号短整型，取值范围是0~65535，输入的值大于65535就会发生溢出，最后得到size为4，这样会通过边界检查，但是用memcpy复制数据的时候，使用的是int类型的参数i，这个值是输入的65540，就会发生栈溢出：

![](https://bbs.kanxue.com/upload/attach/201907/823237_KQH6XEUXZXP5CZ6.png)

#### 基于堆的整数溢出

基于堆的整数溢出的例子：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

24

25

26

27

28

29|`int` `main(``int` `argc, char``*` `argv)`

`{`

`int``*` `heap;`

`unsigned short``int` `size;``/``/` `无符号短整数取值范围：``0` `~``65535`

`char``*``pheap1,``*``pheap2;`

`HANDLE hHeap;`

`printf(``"输入size数值：\n"``);`

`scanf(``"%d"``,&size);`

`hHeap``=` `HeapCreate(HEAP_GENERATE_EXCEPTIONS,``0x100``,``0xfff``);``/``/``创建一个堆块`

`if` `(size <``=` `0x50``)`

`{`

`size``-``=` `5``;``/``/``输入``2``，size``=``-``3``=``65533``，`

`printf(``"size：%d\n"``,size);`

`pheap1``=` `HeapAlloc(hHeap,``0``, size);``/``/` `pheap1会分配过大的堆块，导致溢出！`

`pheap2``=` `HeapAlloc(hHeap,``0``,``0x50``);`

`}`

`HeapFree(hHeap,``0``, pheap1);`

`HeapFree(hHeap,``0``, pheap2);`

`return` `0``;`

`}`|


代码中的size是unsigned short int类型，当输入小于5，size减去5会得到负数，但由于unsigned short int取值范围的限制无法识别负数，得到正数65533，最后分配得到过大的堆块，溢出覆盖了后面的堆管理结构：

![](https://bbs.kanxue.com/upload/attach/201907/823237_PAADHV3M4WG4EKJ.png)

格式化漏洞产生的原因主要是对用户输入的内容没有做过滤，有些输入数据都是作为参数传递给某些执行格式化操作的函数的，比如：printf，fprintf，vprintf，sprintf。

恶意用户可以使用%s和%x等格式符，从堆栈和其他内存位置输出数据，也可以使用格式符%n向任意地址写入数据，配合printf（）函数就可以向任意地址写入被格式化的字节数，可能导致任意代码执行，或者读取敏感数据。

以下面的代码为例讲解格式化字符串漏洞原理：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12|`int` `main (``int` `argc, char``*``argv[])`

`{`

`char buff[``1024``];``/``/` `设置栈空间`

`strncpy(buff,argv[``1``],sizeof(buff)``-``1``);`

`printf(buff);``/``/``触发漏洞`

`return` `0``;`

`}`|


可以发现当输入数据包含%s和%x格式符的时候，会意外输出其他数据：

![](https://bbs.kanxue.com/upload/attach/201907/823237_8U5FKBQVD2BMETM.png)

用ollydbg附加调试程序，执行前需要先设置命令行参数，调试-参数-命令行：test-%x

![](https://bbs.kanxue.com/upload/attach/201907/823237_R9EWRBXBUNS3HJ2.png)

在运行程序后，传递给printf的参数只有test-%x，但是他把输入参数test-%x之后的另一个栈上数据当做参数传给了printf函数，因为printf基本类型是：

传递给printf的参数只有一个，但是程序默认将栈上的下一个数据作为参数传递给了printf函数，刚好下一个数据是strcpy（）函数的目标地址，就是buff变量，buff刚好指向test-%x的地址0x0019fec4，所以程序会输出0x0019fec4，如果后面再加一个%x就会将src参数的值也输出了，这样就可以遍历整个栈上数据了。

![](https://bbs.kanxue.com/upload/attach/201907/823237_TNYP7VTVUVZCP9E.png)

除了利用%x读取栈上数据，还可以用%n写入数据修改返回地址来实现漏洞利用。

Double Free漏洞是由于对同一块内存进行二次释放导致的，利用漏洞可以执行任意代码，编译成release示例代码如下：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

24

25

26|`int` `main (``int` `argc, char``*``argv[])`

`{`

`void``*``p1,``*``p2,``*``p3;`

`p1``=` `malloc(``100``);`

`printf(``"Alloc p1：%p\n"``,p1);`

`p2``=` `malloc(``100``);`

`printf(``"Alloc p2：%p\n"``,p2);`

`p3``=` `malloc(``100``);`

`printf(``"Alloc p3：%p\n"``,p3);`

`printf(``"Free p1\n"``);`

`free(p1);`

`printf(``"Free p3\n"``);`

`free(p3);`

`printf(``"Free p2\n"``);`

`free(p2);`

`printf(``"Double Free p2\n"``);``/``/``二次释放`

`free(p2);`

`return` `0``;`

`}`|


在二次释放p2的时候就会发生程序崩溃，但是并不是每次出现Double Free都会发生崩溃，要有堆块合并的动作发生才会发生崩溃

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

24

25|`int` `main (``int` `argc, char``*``argv[])`

`{`

`void``*``p1,``*``p2,``*``p3;`

`p1``=` `malloc(``100``);`

`printf(``"Alloc p1：%p\n"``,p1);`

`p2``=` `malloc(``100``);`

`printf(``"Alloc p2：%p\n"``,p2);`

`p3``=` `malloc(``100``);`

`printf(``"Alloc p3：%p\n"``,p3);`

`printf(``"Free p2\n"``);`

`free(p2);`

`printf(``"Double Free p2\n"``);`

`free(p2);`

`printf(``"Free p1\n"``);`

`free(p1);`

`printf(``"Free p3\n"``);`

`free(p3);`

`return` `0``;`

`}`|


![](https://bbs.kanxue.com/upload/attach/201907/823237_NDJY7Y3DN2JNGJR.png)

![](https://bbs.kanxue.com/upload/attach/201907/823237_ZWRBMXBMCJF5MTN.png)

双重释放原理图

在释放过程中，邻近的已经释放的堆块存在合并操作，这会改变原有堆头信息，之后再对其地址引用释放就会发生访问异常。

通过以下代码理解UAF漏洞原理：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22

23

24

25

26

27

28|`int` `main(``int` `argc, char``*``*``argv) {`

`char``*``buf1;`

`char``*``buf2;`

`buf1``=` `(char``*``) malloc(size);`

`printf(``"buf1：0x%p\n"``, buf1);`

`free(buf1);`

`/``/` `分配 buf2 去“占坑”buf1 的内存位置`

`buf2``=` `(char``*``) malloc(size);`

`printf(``"buf2：0x%p\n\n"``, buf2);`

`/``/` `对buf2进行内存清零`

`memset(buf2,``0``, size);`

`printf(``"buf2：%d\n"``,``*``buf2);`

`/``/` `重引用已释放的buf1指针，但却导致buf2值被篡改`

`printf(``"==== Use After Free ===\n"``);`

`strncpy(buf1,``"hack"``,``5``);`

`printf(``"buf2：%s\n\n"``, buf2);`

`free(buf2);`

`}`|


![](https://bbs.kanxue.com/upload/attach/201907/823237_NKBGPT28K3B4Y82.png)

buf2 “占坑”了buf1 的内存位置，经过UAF后，buf2被成功篡改了

程序通过分配和buf1大小相同的堆块buf2实现占坑，似的buf2分配到已经释放的buf1内存位置，但由于buf1指针依然有效，并且指向的内存数据是不可预测的，可能被堆管理器回收，也可能被其他数据占用填充，buf1指针称为悬挂指针，借助悬挂指针buf1将内存赋值为hack，导致buf2也被篡改为hack。

如果原有的漏洞程序引用到悬挂指针指向的数据用于执行指令，就会导致任意代码执行。

在通常的浏览器UAF漏洞中，都是某个C++对象被释放后重引用，假设程序存在UAF的漏洞，有个悬挂指针指向test对象，要实现漏洞利用，通过占坑方式覆盖test对象的虚表指针，虚表指针指向虚函数存放地址，现在让其指向恶意构造的shellcode，当程序再次引用到test对象就会导致任意代码执行。

![](https://bbs.kanxue.com/upload/attach/201907/823237_3PMDQ7RBF3SWTMT.png)

UAF漏洞利用原理图

先区分一下数组越界漏洞和溢出漏洞：数组越界访问包含读写类型，溢出属于数据写入；部分溢出漏洞本质确实就是数组越界漏洞。

数组越界就像是倒水的时候倒错了杯子，溢出就像是水从杯子里溢出来。

下面代码为例分析数组越界访问漏洞：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13|`int` `main(){`

`int` `index;`

`int` `array[``3``]``=` `{``0x11``,``0x22``,``0x33``};`

`printf(``"输入数组索引下标："``);`

`scanf(``"%d"``, &index);`

`printf(``"输出数组元素：array[%d] = 0x%x\n"``, index, array[index]);``/``/``数组越界读操作`

`/``/``array[index]``=` `1` `;``/``/``数组越界写操作`

`return` `0``;`

`}`|


![](https://bbs.kanxue.com/upload/attach/201907/823237_6QPEMQK29DJJKUC.png)

执行生成的程序，然后分别输入12345，输出结果如上，当输入的数组下标分别是12的时候，会得到正常数值，但是从索引3开始就超出了原来的数组array的范围，比如输入5，就会数组越界访问array数组，导致读取不在程序控制范围内的数值。

使用ollydbg调试发现array\[5\]就是从array开始的第六个数据0x4012A9，已经读取到了array之外的数据，如果越界访问距离过大，就会访问到不可访问的内存空间，导致程序崩溃。

类型混淆漏洞（Type Confusion）一般是将数据类型A当做数据类型B来解析引用，这就可能导致非法访问数据从而执行任意代码，比如将Unit转成了String，将类对象转成数据结构。

类型混淆漏洞是现在浏览器漏洞挖掘的主流漏洞，这类漏洞在java，js等弱类型语言中非常常见。

下面的代码，A类被混淆成B类，就可能导致私有域被外部访问到：

```
class A {
    private int value;
};

class B {
    public int value;
};

B attack = AcastB(var); //将A类型混淆转成B类型
attack.value = 1; //导致可以访问私有域
```

以IE/Edge类型混淆漏洞（CVE-2017-0037）为例讲解，漏洞原因是函数处理时，没有对对象类型进行严格检查，导致类型混淆。

PoC如下：在PoC中定义了一个table，标签中定义了表id为th1，在boom()中引用，然后是setInterval设定事件。

![](https://bbs.kanxue.com/upload/attach/201907/823237_UN8JVAMG8AV4YJH.png)

运行PoC，用Windbg附加并加载运行出现崩溃

![](https://bbs.kanxue.com/upload/attach/201907/823237_WU27V2Z6WXKG7N5.png)

从崩溃点可以看到eax作为指针，引用了一个无效地址，导致崩溃，而上一条指令是一个call，这个无效的返回值来自这个call，在这个call处下断点，ecx作为参数，存放的对象是一个Layout::FlowItem::\`vftable虚表

![](https://bbs.kanxue.com/upload/attach/201907/823237_HK3RZNC3NMXRJFD.png)

这里读取虚表中+4的值，为0时this指针赋值v1，随后v1+16后返回，因此，Layout::FlowItem::\`vftable所属指针的这个情况是正常的，函数会正常返回进入后续处理逻辑

![](https://bbs.kanxue.com/upload/attach/201907/823237_9Q29F845WBECJ39.png)

让程序继续运行，会再次调用该函数，此时ecx并不是一个虚表对象，而是一个int Array对象，这里我们可以通过条件断点来跟踪两个对象的创建过程，重点关注两个对象创建的函数，一个是FlowItem::\`vftable对应的虚表对象，另一个是引发崩溃的int Array对象。这两个函数的返回值，也就是eax寄存器中存放的指向这两个创建对象的指针。

![](https://bbs.kanxue.com/upload/attach/201907/823237_U7KYVVNCMDEFWHV.png)

通过跟踪可以看到第一次调用Readable函数时ecx是一个正常的FlowItem对象，而第二次调用的时候ecx是一个int Array Object。Layout::Patchable >::Readable函数是处理虚表对象的函数，由于boom()函数中引用th1.align导致Readable函数得到第二次引用，由于没有进行对象属性检查，导致第二次调用时将table对象传入，最终发生类型混淆崩溃。

竞争条件（Race Condition）是由于多个线程/对象/进程同时操作同一资源，导致系统执行违背原有逻辑设定的行为，这类漏洞在linux，内核层面非常多见，在windows和web层面也存在。

互斥锁的出现就是为了解决此类漏洞问题，保证某一对象在特定资源访问时，其他对象不能操作此资源。

|||
|---|---|
|1|`竞争条件”发生在多个线程同时访问同一个共享代码、变量、文件等没有进行锁操作或者同步操作的场景中。 ——Wikipedia``-``computer_science`|


比如如下代码：

|||
|---|---|
|1

2

3

4

5

6

7

8

9

10

11

12

13

14

15

16

17

18

19

20

21

22|`import` `threading`

`COUNT``=` `0`

`def` `Run(threads_name):`

`global` `COUNT`

`read_value``=` `COUNT`

`print` `"COUNT in Thread-%s is %d"` `%` `(``str``(threads_name), read_value)`

`COUNT``=` `read_value``+` `1`

`def` `main():`

`threads``=` `[]`

`for` `j``in` `range``(``10``):`

`t``=` `threading.Thread(target``=``Run,args``=``(j,))`

`threads.append(t)`

`t.start()`

`for` `i``in` `range``(``len``(threads)):`

`threads[i].join()`

`print``(``"Finally, The COUNT is %d"` `%` `(COUNT,))`

`if` `__name__``=``=` `'__main__'``:`

`main()`|


执行结果如下：

![](https://bbs.kanxue.com/upload/attach/201907/823237_9WYEPCUCWAAZNAT.png)

按照我们的预想，结果应该都是10，但是发现结果可能存在非预期解，原因就在于我们没有对变量COUNT做同步制约，导致可能Thread-7在读COUNT,还没来得及更改COUNT,Thread-8抢夺资源，也来读COUNT,并且将COUNT修改为它读的结果+1，由此出现非预期。

《漏洞战争》

https://www.jianshu.com/p/bb3aaf3f5890

http://v0w.top/2018/08/16/条件竞争/

个人github博客地址：

https://github.com/streetleague/0xbird.github.io/

个人安全研究公众号平台：

![](https://bbs.kanxue.com/upload/attach/201907/823237_P95QDFE7ZF9BXHK.jpg)


[零基础网络安全攻防-研修见习班](https://www.kanxue.com/book-section_list-154.htm)

嘿！欢迎来到这里，我是你的阅读助手～本文的主要内容如下：

这是一篇介绍二进制漏洞的文章，涵盖了多种

<button>···</button>

Translate

Export