#!/usr/bin/env python3
import os
import sys
import subprocess
import re
import argparse

class BinaryAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.file_info = {}
        self.headers = {}
        self.sections = []
        self.functions = []
        self.strings = []
        
    def analyze(self):
        """Выполнить полный анализ бинарного файла"""
        print(f"[+] Analyzing binary: {self.binary_path}")
        
        self.check_file_type()
        self.get_file_headers()
        self.get_sections()
        self.find_functions()
        self.extract_strings()
        
    def check_file_type(self):
        """Определить тип файла"""
        try:
            result = subprocess.check_output(['file', self.binary_path], text=True)
            self.file_info['type'] = result.strip()
            print(f"[+] File type: {self.file_info['type']}")
        except Exception as e:
            print(f"[-] Error checking file type: {e}")
            
    def get_file_headers(self):
        """Получить информацию о заголовке файла"""
        try:
            result = subprocess.check_output(['readelf', '-h', self.binary_path], text=True)
            print("[+] File Headers:")
            print(result)
            
            # Извлекаем ключевую информацию
            self.headers['entrypoint'] = re.search(r'Entry point address:\s+(0x[0-9a-fA-F]+)', result)
            if self.headers['entrypoint']:
                self.headers['entrypoint'] = self.headers['entrypoint'].group(1)
                
            self.headers['machine'] = re.search(r'Machine:\s+(.*)', result)
            if self.headers['machine']:
                self.headers['machine'] = self.headers['machine'].group(1)
            
        except Exception as e:
            print(f"[-] Error getting file headers: {e}")
            
    def get_sections(self):
        """Получить информацию о секциях файла"""
        try:
            result = subprocess.check_output(['readelf', '-S', self.binary_path], text=True)
            print("[+] Sections:")
            print(result)
            
            # Извлекаем информацию о секциях
            section_pattern = r'\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)'
            self.sections = re.findall(section_pattern, result)
            
            # Выводим наиболее интересные секции
            print("[+] Key sections:")
            for section in self.sections:
                if section[1] in ['.text', '.data', '.bss', '.plt', '.got', '.eh_frame']:
                    print(f"    {section[1]} at 0x{section[3]}")
                    
        except Exception as e:
            print(f"[-] Error getting sections: {e}")
            
    def find_functions(self):
        """Найти функции в бинарном файле"""
        try:
            result = subprocess.check_output(['objdump', '-d', self.binary_path], text=True)
            
            # Ищем определения функций
            function_pattern = r'<([^>+]+)>:'
            self.functions = re.findall(function_pattern, result)
            
            print(f"[+] Found {len(self.functions)} functions:")
            for func in self.functions:
                print(f"    {func}")
                
            # Поиск вызова потенциально уязвимых функций
            vulnerable_funcs = ['gets', 'strcpy', 'strcat', 'scanf', 'vsprintf']
            print("[+] Checking for potentially vulnerable function calls:")
            
            for vuln_func in vulnerable_funcs:
                if f'@plt>{vuln_func}@plt' in result or f'<{vuln_func}>' in result:
                    print(f"    WARNING: Found call to vulnerable function: {vuln_func}")
                    
        except Exception as e:
            print(f"[-] Error finding functions: {e}")
            
    def extract_strings(self):
        """Извлечь строки из бинарного файла"""
        try:
            result = subprocess.check_output(['strings', self.binary_path], text=True)
            self.strings = result.strip().split('\n')
            
            print(f"[+] Extracted {len(self.strings)} strings")
            print("[+] Interesting strings:")
            
            # Показываем интересные строки (командные оболочки, пути, сообщения)
            interesting_patterns = [
                r'/bin/sh', r'/bin/bash', r'password', r'user', r'admin',
                r'flag', r'secret', r'granted', r'access', r'exploit'
            ]
            
            for string in self.strings:
                for pattern in interesting_patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        print(f"    {string}")
                        break
                        
        except Exception as e:
            print(f"[-] Error extracting strings: {e}")
            
    def check_security(self):
        """Проверить наличие мер безопасности"""
        try:
            result = subprocess.check_output(['checksec', '--file', self.binary_path], text=True, stderr=subprocess.DEVNULL)
            print("[+] Security features:")
            print(result)
        except FileNotFoundError:
            # Если checksec не установлен, пробуем проверить вручную
            try:
                nx_result = subprocess.check_output(['readelf', '-l', self.binary_path], text=True)
                if "GNU_STACK" in nx_result and "RWE" in nx_result:
                    print("    Stack is executable (NX disabled)")
                else:
                    print("    NX protection enabled")
                    
                # Проверка на RELRO
                if "BIND_NOW" in nx_result:
                    print("    Full RELRO enabled")
                elif "RELRO" in nx_result:
                    print("    Partial RELRO enabled")
                else:
                    print("    No RELRO protection")
                    
                # Проверка на канарейку
                canary_result = subprocess.check_output(['objdump', '-d', self.binary_path], text=True)
                if "stack_chk_fail" in canary_result:
                    print("    Stack canary enabled")
                else:
                    print("    No stack canary protection")
                    
            except Exception as e:
                print(f"[-] Error checking security features: {e}")
                
def main():
    parser = argparse.ArgumentParser(description="Binary Analysis Tool")
    parser.add_argument('binary', help='Path to the binary file to analyze')
    parser.add_argument('--full', action='store_true', help='Perform full analysis')
    
    args = parser.parse_args()
    
    analyzer = BinaryAnalyzer(args.binary)
    
    if args.full:
        analyzer.analyze()
        analyzer.check_security()
    else:
        analyzer.check_file_type()
        analyzer.find_functions()
        analyzer.extract_strings()
        
if __name__ == "__main__":
    main() 