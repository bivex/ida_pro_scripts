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
        "NtTerminateProcess"
    ]
    
    print("[+] Setting breakpoints on exit functions...")
    
    for func_name in exit_functions:
        # Найти адрес функции
        func_addr = idc.get_name_ea_simple(func_name)
        
        if func_addr != idaapi.BADADDR:
            # Установить breakpoint
            if idc.add_bpt(func_addr):
                print(f"[+] Breakpoint set at {func_name}: 0x{func_addr:X}")
                
                # Для ExitProcess установить условие через другой способ
                if func_name == "ExitProcess":
                    # Установить условный breakpoint
                    condition = "//PYTHON\nGetRegValue('RCX') == 0xFFFFFFFF or GetRegValue('RCX') == 0x80000000 + 0x7FFFFFFF"
                    bpt = ida_dbg.get_bpt(func_addr)
                    if bpt:
                        bpt.condition = condition
                        if ida_dbg.update_bpt(bpt):
                            print(f"[+] Condition set for {func_name}")
                        else:
                            print(f"[-] Failed to update breakpoint for {func_name}")
                    else:
                        print(f"[-] Failed to get breakpoint object for {func_name}")
                else:
                    print(f"[-] Failed to set breakpoint at {func_name}")
        else:
            print(f"[-] Function {func_name} not found")
    
    # Дополнительно - поиск по импортам
    print("\n[+] Checking imports...")
    check_imports()

def check_imports():
    """Проверить импорты на наличие функций выхода"""
    exit_functions = ["exitprocess", "terminateprocess", "exit", "abort", "fatalexit"]
    
    # Получить все импорты
    for i in range(idaapi.get_import_module_qty()):
        module_name = idaapi.get_import_module_name(i)
        if not module_name:
            continue
            
        def import_callback(ea, name, ordinal):
            if name:
                name_lower = name.lower()
                if any(exit_func in name_lower for exit_func in exit_functions):
                    if idc.add_bpt(ea):
                        print(f"[+] Import breakpoint set at {name}: 0x{ea:X}")
                        
                        # Для ExitProcess добавить условие
                        if "exitprocess" in name_lower:
                            condition = "//PYTHON\nGetRegValue('RCX') == 0xFFFFFFFF"
                            bpt = ida_dbg.get_bpt(ea)
                            if bpt:
                                bpt.condition = condition
                                if ida_dbg.update_bpt(bpt):
                                    print(f"[+] Condition set for import {name}")
                                else:
                                    print(f"[-] Failed to update breakpoint for import {name}")
                            else:
                                print(f"[-] Failed to get breakpoint object for import {name}")
            return True
            
        idaapi.enum_import_names(i, import_callback)

def set_custom_monitoring():
    """Установить мониторинг на конкретные адреса"""
    
    # Адрес функции деструктора
    destructor_addr = 0x7FF776A6D950  # Замените на актуальный адрес
    
    if idc.add_bpt(destructor_addr):
        print(f"[+] Destructor breakpoint set at: 0x{destructor_addr:X}")
        
        # Условие для логирования
        log_condition = '''//PYTHON
import idc
print("[DESTRUCTOR HIT] RCX (Block): 0x%X" % idc.get_reg_value("RCX"))
print("[STACK] RSP: 0x%X" % idc.get_reg_value("RSP"))
False  # Всегда продолжать выполнение
'''
        bpt = ida_dbg.get_bpt(destructor_addr)
        if bpt:
            bpt.condition = log_condition
            if ida_dbg.update_bpt(bpt):
                print(f"[+] Condition set for destructor")
            else:
                print(f"[-] Failed to update breakpoint for destructor")
        else:
            print(f"[-] Failed to get breakpoint object for destructor")

def find_exit_calls():
    """Найти все вызовы функций выхода в коде"""
    
    print("[+] Searching for exit function calls...")
    
    # Поиск по всему сегменту кода
    start_ea = idc.get_segm_start(idc.here())
    end_ea = idc.get_segm_end(idc.here())
    
    exit_patterns = [
        "ExitProcess",
        "TerminateProcess",
        "exit",
        "abort"
    ]
    
    current_ea = start_ea
    while current_ea < end_ea:
        # Проверить, есть ли вызов функции
        if idc.print_insn_mnem(current_ea) == "call":
            # Получить операнд вызова
            operand = idc.print_operand(current_ea, 0)
            
            # Проверить, содержит ли имя функции выхода
            for pattern in exit_patterns:
                if pattern.lower() in operand.lower():
                    print(f"[+] Found {pattern} call at 0x{current_ea:X}")
                    
                    # Установить breakpoint
                    if idc.add_bpt(current_ea):
                        print(f"[+] Breakpoint set at call site: 0x{current_ea:X}")
        
        current_ea = idc.next_head(current_ea)

def monitor_stack_and_exit():
    """Альтернативный способ мониторинга через трассировку стека"""
    
    print("[+] Setting up stack monitoring...")
    
    # Найти все функции с "exit" в имени
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        if func_name and "exit" in func_name.lower():
            if idc.add_bpt(func_ea):
                print(f"[+] Stack monitor BP at {func_name}: 0x{func_ea:X}")

def quick_setup():
    """Быстрая настройка для отладки"""
    
    print("=== QUICK EXIT MONITORING SETUP ===")
    
    # 1. ExitProcess
    exit_addr = idc.get_name_ea_simple("ExitProcess")
    if exit_addr != idaapi.BADADDR:
        idc.add_bpt(exit_addr)
        # Простое условие
        condition = "//PYTHON\nprint('ExitProcess called with code:', hex(idc.get_reg_value('RCX'))); False"
        bpt = ida_dbg.get_bpt(exit_addr)
        if bpt:
            bpt.condition = condition
            if ida_dbg.update_bpt(bpt):
                print(f"[+] ExitProcess monitor at 0x{exit_addr:X}")
            else:
                print(f"[-] Failed to update breakpoint for ExitProcess")
        else:
            print(f"[-] Failed to get breakpoint object for ExitProcess")
    
    # 2. TerminateProcess  
    term_addr = idc.get_name_ea_simple("TerminateProcess")
    if term_addr != idaapi.BADADDR:
        idc.add_bpt(term_addr)
        print(f"[+] TerminateProcess monitor at 0x{term_addr:X}")
    
    # 3. Функция деструктора
    current_addr = idc.here()
    if current_addr != idaapi.BADADDR:
        idc.add_bpt(current_addr)
        print(f"[+] Current address monitor at 0x{current_addr:X}")

def main():
    """Главная функция скрипта"""
    
    print("=== EXIT CODE -1 MONITOR (IDA 9.1) ===")
    
    try:
        # Основная настройка
        set_exit_breakpoints()
        
        # Поиск вызовов в коде
        find_exit_calls()
        
        # Быстрая настройка
        print("\n" + "="*50)
        quick_setup()
        
        print("\n[+] Monitoring setup complete!")
        print("[+] Start debugging (F9) to monitor exit calls")
        print("[+] Breakpoints will show exit codes and call stacks")
        
    except Exception as e:
        print(f"[-] Error during setup: {e}")
        print("[+] Trying quick setup instead...")
        quick_setup()

# Вспомогательные функции для консоли
def bp_exit():
    """Быстрая команда для установки BP на ExitProcess"""
    addr = idc.get_name_ea_simple("ExitProcess")
    if addr != idaapi.BADADDR:
        idc.add_bpt(addr)
        print(f"ExitProcess BP: 0x{addr:X}")

def bp_here():
    """Установить BP на текущий адрес"""
    addr = idc.here()
    idc.add_bpt(addr)
    print(f"Breakpoint set at: 0x{addr:X}")

# Запуск
if __name__ == "__main__":
    main()
