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
 
 
