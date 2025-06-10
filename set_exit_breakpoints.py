import idaapi
import idc
import ida_dbg

def set_exit_breakpoints():
    """Установить breakpoint'ы на функции выхода с кодом -1"""
    
    # Список функций выхода для мониторинга
    exit_functions = [
        "ExitProcess",
        "TerminateProcess", 
        "exit",
        "_exit",
        "abort",
        "FatalExit",
        "FatalAppExit",
        "FatalAppExitA",
        "FatalAppExitW",
        "RtlExitUserProcess",
        "NtTerminateProcess",
        "_CxxThrowException",
        "RaiseException"
    ]
    
    print("[+] Setting breakpoints on exit functions...")
    
    for func_name in exit_functions:
        # Найти адрес функции
        func_addr = idc.get_name_ea_simple(func_name)
        
        if func_addr != idaapi.BADADDR:
            # Установить breakpoint
            if ida_dbg.add_bpt(func_addr):
                print(f"[+] Breakpoint set at {func_name}: 0x{func_addr:X}")
                
                # Установить условие для ExitProcess (проверить код выхода -1)
                if func_name == "ExitProcess":
                    # Условие: проверить первый аргумент (RCX) == -1 или 0xFFFFFFFF
                    condition = "($rcx == 0xFFFFFFFF) || ($rcx == -1)"
                    ida_dbg.set_bpt_cond(func_addr, condition)
                    print(f"[+] Condition set for {func_name}: {condition}")
            else:
                print(f"[-] Failed to set breakpoint at {func_name}")
        else:
            print(f"[-] Function {func_name} not found")
    
    # Дополнительно - поиск по импортам
    print("\n[+] Checking imports...")
    
    def check_imports():
        """Проверить импорты на наличие функций выхода"""
        nim = idaapi.get_import_module_qty()
        
        for i in range(nim):
            name = idaapi.get_import_module_name(i)
            if not name:
                continue
                
            def cb(ea, name, ord):
                if name:
                    name_lower = name.lower()
                    if any(exit_func.lower() in name_lower for exit_func in exit_functions):
                        if ida_dbg.add_bpt(ea):
                            print(f"[+] Import breakpoint set at {name}: 0x{ea:X}")
                            
                            # Условие для ExitProcess
                            if "exitprocess" in name_lower:
                                condition = "($rcx == 0xFFFFFFFF) || ($rcx == -1)"
                                ida_dbg.set_bpt_cond(ea, condition)
                                print(f"[+] Condition set for import {name}: {condition}")
                return True
                
            idaapi.enum_import_names(i, cb)
    
    check_imports()
    
    print("\n[+] Breakpoints setup complete!")
    print("[+] Run the program and check debugger when exit code -1 is hit")

def set_custom_exit_bp():
    """Установить breakpoint на конкретный адрес с условием"""
    
    # Если знаете конкретный адрес где происходит выход
    target_addr = idc.here()  # Текущий адрес в IDA
    
    if target_addr != idaapi.BADADDR:
        if ida_dbg.add_bpt(target_addr):
            print(f"[+] Custom breakpoint set at: 0x{target_addr:X}")
            
            # Добавить логирование в breakpoint
            script = '''
print("[BREAKPOINT HIT] Address: 0x%X" % GetCurrentAddress())
print("[REGISTERS] RAX: 0x%X, RCX: 0x%X, RDX: 0x%X" % (GetRegValue("RAX"), GetRegValue("RCX"), GetRegValue("RDX")))
print("[STACK] RSP: 0x%X" % GetRegValue("RSP"))

# Показать стек вызовов
import ida_dbg
import idautils

def print_call_stack():
    print("[CALL STACK]")
    for i, frame in enumerate(idautils.Threads()):
        if i > 10:  # Ограничить вывод
            break
        print(f"Frame {i}: 0x{frame:X}")

print_call_stack()
'''
            ida_dbg.set_bpt_cond(target_addr, script)

def monitor_specific_function():
    """Мониторинг конкретной функции"""
    
    # Адрес функции sub_7FF776A6D950 (замените на актуальный)
    func_addr = 0x7FF776A6D950  # Ваша функция деструктора
    
    if ida_dbg.add_bpt(func_addr):
        print(f"[+] Monitoring function at: 0x{func_addr:X}")
        
        # Скрипт для логирования
        monitor_script = '''
print("[DESTRUCTOR CALLED] Address: 0x%X" % GetCurrentAddress())
print("[ARG] Block pointer (RCX): 0x%X" % GetRegValue("RCX"))

# Проверить Block[7]
block_ptr = GetRegValue("RCX")
if block_ptr != 0:
    try:
        obj_ptr = Qword(block_ptr + 0x38)  # Block[7]
        print("[OBJECT] Block[7] pointer: 0x%X" % obj_ptr)
    except:
        print("[ERROR] Cannot read Block[7]")
'''
        ida_dbg.set_bpt_cond(func_addr, monitor_script)

# Основная функция
def main():
    """Главная функция скрипта"""
    
    if not ida_dbg.is_debugger_on():
        print("[-] Debugger is not active. Please start debugging first.")
        return
    
    print("=== EXIT CODE -1 MONITOR ===")
    
    # Установить все breakpoint'ы
    set_exit_breakpoints()
    
    # Мониторинг конкретной функции (опционально)
    # monitor_specific_function()
    
    print("\n[+] Script completed. Start/continue execution to monitor exits.")
    print("[+] When breakpoint hits, check call stack and registers.")

# Запуск скрипта
if __name__ == "__main__":
    main()
