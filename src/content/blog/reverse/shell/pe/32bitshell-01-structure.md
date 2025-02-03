---
title: PE文件加壳（一）--PE文件结构分析
author: ermu0
slug: pe-structure
featured: false
draft: false
tags:
  - Reverse
  - Pe
pubDatetime: 2024-12-9T19:43:09+08:00
modDatatime: 2024-12-9T19:43:09+08:00
description: 对PE文件进行简单分析，为后续加壳作一个简单的理论铺垫
---

本来想一次性把加壳给写完，发现还是得分成2部分。

对PE文件的格式有一个简单的了解后，在进行加壳时会更容易理解，上手也会更快。

由于网上有太多的佬（比如：看雪[^1]、伟牛牛[^2]、吾爱[^3]）对PE文件结构进行了详细说明，这里我就不多赘述，只简单说一下（作个记录），后面我会在参考链接中给出相关帖子。

## 1. PE文件结构图

先给出整个PE文件结构图：
![PE结构图](https://bbs.kanxue.com/upload/attach/202002/813468_PZCYNX9G8HN2YUB.png)

下面再对上图的部分结构进行一个大致的说明。

## 2. DOS头

### 2.1 IMAGE_DOS_HEADER

先来看**DOS-header**字段，下面给出该字段的结构信息：

```c
typedef struct _IMAE_DOS_HEADER {       
    WORD e_magic;        **重要成员 相对该结构的偏移0x00**
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;        **重要成员 相对该结构的偏移0x3C**
} IMAGE_DOS-HEADER, *PIMAGE_DOS_HEADER;
```

其中有两个需要注意的字段，

- **magic**字段（2字节）：magic字段是一个固定值，它的十六进制值是固定的4D5A，转为Ascii就是**MZ**。
- **e_lfanew**字段（4字节）：它的字段值代表着NT头的偏移地址，也就是说只有通过读取这个e_lfanew字段值，才能找到NT头的起始地址。

### 2.2 IMAGE_DOS_STUB

**IMAGE_DOS_STUB**不用太过注意，这段值基本上是固定的，就是一句话:

`This program cannot be run in DOS mode `

## 3. NT头

NT头是整个PE文件中的核心，它的结构如下所示：

```c
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;         **重要成员 PE签名 相对该结构的偏移0x00**
  IMAGE_FILE_HEADER       FileHeader;        **重要成员 结构体 相对该结构的偏移0x04**
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;    **重要成员 结构体 相对该结构的偏移0x18**
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

这三个字段都值得注意！

### 3.1 Signature

这个字段也被称作PE签名，这个成员和DOS头中的MZ标记一样都是PE文件的标准特征。

### 3.2 FileHeader

FileHeader是一个IMAGE_FILE_HEADER类型的结构体，具体大小要看内部数据类型，它的具体结构如下：

```c
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;                    **        机器号     相对该结构的偏移0x00**
  WORD  NumberOfSections;           **重要成员 节区数量   相对该结构的偏移0x02**
  DWORD TimeDateStamp;              **        时间戳     相对该结构的偏移0x04**
  DWORD PointerToSymbolTable;       **        符号表偏移  相对该结构的偏移0x08**
  DWORD NumberOfSymbols;            **        符号表数量  相对该结构的偏移0x0C**
  WORD  SizeOfOptionalHeader;       **重要成员 可选头大小  相对该结构的偏移0x10**
  WORD  Characteristics;            **重要成员 PE文件属性  相对该结构的偏移0x12**
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

 在这个结构下有三个需要注意的字段：

- **NumberOfSections**（2字节）：当前PE文件中的节区数量，虽然它的大小为2字节，但在Windows加载程序时会将节区的最大数量限制为96个。

- **SizeOfOptionalHeader**（2字节）：它存储该PE文件的可选PE头的大小。

- **Characteristics**（2字节）：描述了PE文件的一些属性信息，比如是否可执行，是否是一个动态链接库等。

### 3.3 OptionalHeader

OptionalHeader是一个IMAGE_OPTIONAL_HEADER32类型的结构体，它的结构如下：

```c
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;                        **魔术字                     偏移0x00
  BYTE                 MajorLinkerVersion;           **链接器主版本                偏移0x02
  BYTE                 MinorLinkerVersion;           **链接器副版本                偏移0x03
  DWORD                SizeOfCode;                   **所有含代码的节的总大小       偏移0x04
  DWORD                SizeOfInitializedData;        **所有含初始数据的节的总大小    偏移0x08
  DWORD                SizeOfUninitializedData;      **所有含未初始数据的节的总大小  偏移0x0C    
  DWORD                AddressOfEntryPoint;          **程序执行入口地址             偏移0x10   重要
  DWORD                BaseOfCode;                   **代码节的起始地址             偏移0x14
  DWORD                BaseOfData;                   **数据节的起始地址             偏移0x18
  DWORD                ImageBase;                    **程序首选装载地址             偏移0x1C   重要
  DWORD                SectionAlignment;             **内存中节区对齐大小           偏移0x20   重要
  DWORD                FileAlignment;                **文件中节区对齐大小           偏移0x24   重要
  WORD                 MajorOperatingSystemVersion;  **操作系统的主版本号           偏移0x28
  WORD                 MinorOperatingSystemVersion;  **操作系统的副版本号           偏移0x2A
  WORD                 MajorImageVersion;            **镜像的主版本号               偏移0x2C
  WORD                 MinorImageVersion;            **镜像的副版本号               偏移0x2E
  WORD                 MajorSubsystemVersion;        **子系统的主版本号             偏移0x30
  WORD                 MinorSubsystemVersion;        **子系统的副版本号             偏移0x32
  DWORD                Win32VersionValue;            **保留，必须为0               偏移0x34
  DWORD                SizeOfImage;                  **镜像大小                    偏移0x38   重要
  DWORD                SizeOfHeaders;                **PE头大小                    偏移0x3C   重要
  DWORD                CheckSum;                     **校验和                      偏移0x40
  WORD                 Subsystem;                    **子系统类型                   偏移0x44
  WORD                 DllCharacteristics;           **DLL文件特征                  偏移0x46
  DWORD                SizeOfStackReserve;           **栈的保留大小                 偏移0x48
  DWORD                SizeOfStackCommit;            **栈的提交大小                 偏移0x4C
  DWORD                SizeOfHeapReserve;            **堆的保留大小                 偏移0x50
  DWORD                SizeOfHeapCommit;             **堆的提交大小                 偏移0x54
  DWORD                LoaderFlags;                  **保留，必须为0                偏移0x58
  DWORD                NumberOfRvaAndSizes;          **数据目录的项数               偏移0x5C
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

 需要注意的内容主要是下面几个：

- **magic**（2字节）：指出了镜像文件的状态，可以是以下值：

  - 0x010B：表明这是一个32位镜像文件。

  - 0x020B：表明这是一个64位镜像文件。

  - 0x0107：表明这是一个ROM镜像。

- **AddressOfEntryPoint**（4字节）：该字段是文件执行时的入口地址，字段值实际存的是一个RVA，所以需要加上基址才能得到才能得到程序在内存中的运行地址VA。另外，如果想要在一个可执行文件中附加一段代码并且要让这段代码先被执行，就需要更改入口地址到目标代码上，然后再跳转回原有的入口地址。

- **ImageBase**（4字节）：这个字段就是文件基址。但可能出现地址被占用的情况（这个后面碰见了再细说）

- **SectionAlignment**（4字节）：文件被加载到内存后的节区对齐单位，节区被装入内存的虚拟地址必须是该成员的整数倍。（对齐就好比书本页一样，每个节区的内容就拓印在书本页上，即使当前节区的内容不足一页，但仍将剩下的页面给予当前节区，这样一来，翻书的时候只需要在目录告知哪几页是哪个节区的内容，这样一来就比不对齐——一页上面有多个节区内容要好找得多）

- **FileAlignment**（4字节）：文件在硬盘上存储时的节区对齐单位。节区在硬盘上的地址必须是该成员的整数倍。

- **SizeOfImage**（4字节）：文件被加载到内存后的总体大小，它的值应该是SectionAlignment的整数倍。

- **SizeOfHeaders**（4字节）：PE文件头的大小，它的计算方式如下：

 ```c
SizeOfHeaders = (e_lfanew/*DOS头部*/ +　4/*PE签名*/ +
                sizeof(IMAGE_FILE_HEADER) +
                SizeOfOptionalHeader + /*NT头*/
                sizeof(IMAGE_SECTION_HEADER) * NumberOfSections) / /*节表*/
                FileAlignment  *
                FileAlignment +
                FileAlignment;    /*向上舍入 一般该结果不可能是FileAlignment的整数倍，所以直接加上FileAlignment还是没问题的 */
 ```

- **NumberOfRvaAndSizes**：指定了可选头中目录项的具体数目。

- **DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]**：数据目录结构。这个结构用来描述PE中各个表的位置以及大小信息，比如：导出表、导入表、重定位表、资源表等。也就是说这个目录结构下的每一个元素都是一个表结构体类型（我自称的），而这个表结构体类型的结构如下：

  ```c
  // 数据目录 _IMAGE_DATA_DIRECTORY结构体
  typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;     /**指向某个数据的相对虚拟地址   RAV  偏移0x00**/
    DWORD Size;               /**某个数据块的大小                 偏移0x04**/
  } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
  ```

  不难看出，表结构类型的结构体只有两个属性：**相对偏移地址**和**所指向的数据块的大小**。

  在目录结构中，各个类型的表的排列是固定，下面给出各个表类型的相关信息：

  ![不同表的下标](https://bbs.kanxue.com/upload/attach/202111/919233_BRRDKGZZY3A2JH2.jpg)

由于本文章内容主要是实现加壳操作，所以只探究导入表和导入地址表，这里以导入表为例子。

导入表的每一项也是一个结构体，用于描述一个DLL文件及其相关的导入信息，结构如下：

  ```c
  typedef struct _IMAGE_IMPORT_DESCRIPTOR {
      DWORD OriginalFirstThunk;   // 指向导入名称表（INT），保存导入函数的原始信息
      DWORD TimeDateStamp;        // 时间戳（调试用）
      DWORD ForwarderChain;       // 转发链（调试用）
      DWORD Name;                 // 指向 DLL 名称的 RVA（相对于文件基址的偏移）
      DWORD FirstThunk;           // 指向导入地址表（IAT）
  } IMAGE_IMPORT_DESCRIPTOR;
  ```

  这里主要关注三个字段：

  - **OriginalFirstThunk**：指向IDT表的RVA
  - **Name**：虽然名字感觉像是DLL的name，实际上还是一个RVA，需要利用基址来计算VA才能得到名字
  - **FirstThunk**：指向IAT表的RVA

  上面的IDT与IAT（未修改前）中的每一项也都是一个结构体，结构如下：

  ```c
  typedef struct _IMAGE_THUNK_DATA {
      union {
          DWORD Function;            // 实际函数地址
          DWORD Ordinal;             // 按序号导入时的序号
          DWORD AddressOfData;       // 按名称导入时的指针
      } u1;
  } IMAGE_THUNK_DATA;
  ```

  这里着重关注AddressofData字段，这个字段值有两种情况：偏移值 或者 序号值

  - 偏移值加上基址后指向的是个结构体：这个结构体叫做**IMAGE_IMPORT_BY_NAME**，在该结构体下有一个Name字段，该字段是一个地址，存储的是DLL中某个函数名称，然后通过GetProcAddress函数，就能得到DLL加载进内存后，其中映射到内存中的函数地址。
  - 序号值：同样利用GetProcAddress函数，就能直接得到映射到内存中的函数地址。

  最后将得到的函数地址放进对应的IAT表中修改，就能完成对IAT的修改。

## 4. SECTION头

一个PE文件中回包含多个section头，具体的数量需要参考FileHeader中的NumberOfSections字段。

secition头的结构如下：

```c
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];         **节区名                 偏移0x00
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;                         **节区的虚拟大小          偏移0x08      重要
  } Misc;                                     
  DWORD VirtualAddress;                        **节区的虚拟地址          偏移0x0C      重要  
  DWORD SizeOfRawData;                         **节区在硬盘上的大小       偏移0x10      重要
  DWORD PointerToRawData;                      **节区在硬盘上的地址       偏移0x14      重要
  DWORD PointerToRelocations;                  **指向重定位项开头的地址   偏移0x18
  DWORD PointerToLinenumbers;                  **指向行号项开头的地址     偏移0x1C
  WORD  NumberOfRelocations;                   **节区的重定位项数         偏移0x20
  WORD  NumberOfLinenumbers;                   **节区的行号数            偏移0x22
  DWORD Characteristics;                       **节区的属性              偏移0x24       重要
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

其中需要注意的字段有：

- **VirtualSize**（4字节）：节区被加载到内存后的总大小（可以粗俗理解为实际大小）。
- **VirtualAddress**（4字节）：说是虚拟地址，但实际上是节区被加载到内存后的RVA，需要加上ImageBase基址来计算VA。它的值一般是SectionAlignment的整数倍。
- **SizeOfRawData**（4字节）：节区在磁盘上的大小（注意与VirtualSize区分），它的值必须是FileAlignment的整数倍。
- **PointerToRawData**（4字节）：节区在磁盘上的偏移地址FOA，它的值必须是FileAlignment的整数倍。

## 参考链接

[^1]:[https://bbs.kanxue.com/thread-252795.htm#msg_header_h2_2](https://bbs.kanxue.com/thread-252795.htm#msg_header_h2_2)

[^2]:[https://jev0n.com/2020/02/02/start.html](https://jev0n.com/2020/02/02/start.html)
[^3]:[https://www.52pojie.cn/thread-1520945-1-1.html](https://www.52pojie.cn/thread-1520945-1-1.html)

