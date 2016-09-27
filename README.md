# PyCheat
Another process's memory access and modulation on Windows (like Cheat Engine)

## PyCheat 소스 분석하기
###사용 모듈  
* sys :  
 * sys - platform :  
 * sys - maxsize :  
 * sys - exit :  

* ctype :  
 * ctypes - windll :  
 * ctypes - wintypes :  
 * ctypes - POINTER :  
 * ctypes - Structure :  
 * ctypes - Union :  
 * ctypes - addressof :  
 * ctypes - byref :  
 * ctypes - cast :  
 * ctypes - create_unicode_buffer :  
 * ctypes - create_string_buffer :  
 * ctypes - c_bool : _Bool / bool(1) (C Type / Python Type)  
 * ctypes - c_char : char / 
 * ctypes - c_ubyte : unsigned char / 
 * ctypes - c_byte  : char / 
 * ctypes - c_short : short / int  
 * ctypes - c_int : int / int  
 * ctypes - c_uint16 : unsigned short / int  
 * ctypes - c_uint32 : unsigned long / 
 * ctypes - c_uint64 :  
 * ctypes - c_long : long / 
 * ctypes - c_longlong : __int64 or long long / 
 * ctypes - c_ulong : unsigned long / 
 * ctypes - c_ulonglong : unsigned long long / int  
 * ctypes - c_ushort : unsigned short / int   
 * ctypes - c_void_p : void * / 
 * ctypes - c_char_p : char * / 
 * ctypes - c_wchar_p : wchar_t * / 
 * ctypes - c_size_t :  
 * ctypes - sizeof :  
 * ctypes - c_ARRAY(ARRAY as c_ARRAY) :  
 * ctypes - WinError :  
* struct : 파이썬 문자열을 C 구조체로의 변환을 제공  
* time : 시간 모듈  
* inspect : 런타임 Objectdml 정보를 얻을 수 있게 도와주는 모듈(Modules, classes, methods, functions..)  
* logging : 로그 처리를 위한 모듈  
* os : 운영체제에서 제공하는 기능을 제공하는 모듈  
* threading : 스레드 프로그래밍 모듈  
* binascii : 바이너리 데이터와 ASCII 데이터의 상호변환을 제공하는 모듈  
* re : 정규표현식 모듈  
  
###세부 구조  

* engine.common.process
  * def - type_unpack : 자료형 확인 후, 자료형 키워드와 비트 수를 반환
  * class - process : 
    * def - PELoad :  
    * def - write_byte : VirtualProtectEx의 PAGE_EXECUTE_READWRITE 속성을 이용하여 읽고 쓸 수 있게 메모리 보호 상태를 변경한 후 메모리에 문자열 값을 기록. OldProtect 속성을 이용하여 원래 상태로 변경. 읽어온 메모리 값 반환  
    * def - write_binary : c_type의 create_string_buffer 함수를 이용하여 기록할 바이너리 데이터 담은 후 VirtualProtectEx로 메모리 주소 지정 하여 WriteProcessMemory 함수로 바이너리 데이터 기록.
    * def - read_byte : create_string_buffer 함수를 이용하여 읽을 길이(기본 값 4) 지정 후 while문을 이용하여 ReadProcessMemory 함수로 데이터 읽음.
    * def - read_binary : create_string_buffer 함수를 이용하여 읽을 길이(기본 값 4) 지정 후 ReadProcessMemory 함수로 데이터 읽음.
    * def - read : 읽을 데이터가 'string'('s') 일 경우 주소를 read_byte 함수로 전달하고 read_byte 함수로 부터 전달받은 데이터를  for문으로 '\x00'까지 읽어 반환. 읽을 데이터가 'binary' 인 경우 read_binary 함수로 주소를 전달하고 반환된 값을 처리 없이 반환. 읽을 데이터가 'byte'('b')인 경우 read_byte 함수로 주소 전달 후 반환된 값을 처리 없이 반환. 그 밖의 경우 type_unpack 함수로 자료형 키워드와 비트 수를 반환 받은 후 read_byte함수로 데이터를 읽어 데이터 언팩(struct.unpack) 수행.
    * def - write : 기록할 데이터가 'binary' 인 경우 write_binary 함수로 주소 및 데이터를 전달 후 반환된 값을 처리없이 반환. 기록할 데이터가 ('binary' 및)'bytes' 가 아닌 경우 type_unpack 함수로 자료형 키워드와 비트 수를 반환 받은 후 패킹(struct.pack)하여 write_bytes 함수 수행 후 반환된 데이터 처리 없이 반환. 기록할 데이터가 'bytes' 인 경우 write_bytes 함수에 주소와 데이터 전달 후 반환된 데이터 처리 없이 반환.
    * def - get_symbolic_name : 
    * def - getInstruction : read_byte 함수에 주소를 전달하여 길이 32 만큼 데이터를 반환 받은 후 Distorm3Decoder(Maybee -https://github.com/gdabah/distorm) 함수로 디스어셈블하여 반환

* engine.common.util
  * def - thread : threading.Thread 함수를 이용하여 스레드 생성 및 작업 시작(Thread.start)후 Thread 반환

* engine.common.address
