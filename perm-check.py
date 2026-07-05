#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import stat
import pwd
import grp
import argparse
import json
import csv
from datetime import datetime


def get_file_info(filepath):
    """
    Собирает информацию о файле: права, владелец, группа, флаги безопасности.
    Возвращает словарь с данными или None, если доступ запрещен.
    """
    try:
        st = os.lstat(filepath)
        mode = st.st_mode

        # Человекочитаемый вид прав (например, -rwxrwxrwx)
        permissions = stat.filemode(mode)
        # Восьмеричное представление прав (например, 0777)
        octal_perms = oct(stat.S_IMODE(mode))

        # Получение имени владельца и группы
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)

        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)

        # Определение типа файла
        if stat.S_ISDIR(mode):
            ftype = "Каталог"
        elif stat.S_ISLNK(mode):
            ftype = "Ссылка"
        else:
            ftype = "Файл"

        # Флаги безопасности
        is_world_writable = bool(mode & stat.S_IWOTH)
        is_executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        is_777 = (stat.S_IMODE(mode) == 0o777)

        return {
            "path": filepath,
            "type": ftype,
            "permissions": permissions,
            "octal": octal_perms,
            "owner": owner,
            "group": group,
            "is_world_writable": is_world_writable,
            "is_executable": is_executable,
            "is_777": is_777,
            "is_unsafe": is_777 or is_world_writable
        }
    except PermissionError:
        # ИСПРАВЛЕНО: убрана f-строка
        print("[ПРЕДУПРЕЖДЕНИЕ] Нет прав для доступа к: {}".format(filepath), file=sys.stderr)
        return None
    except OSError as e:
        # ИСПРАВЛЕНО: убрана f-строка
        print("[ОШИБКА] Не удалось получить инфо о {}: {}".format(filepath, e), file=sys.stderr)
        return None


def scan_directory(path):
    """
    Рекурсивно обходит каталог и собирает информацию обо всех объектах.
    """
    results = []
    if not os.path.exists(path):
        # ИСПРАВЛЕНО
        print("[ОШИБКА] Путь не существует: {}".format(path), file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(path):
        # ИСПРАВЛЕНО
        print("[ОШИБКА] Указанный путь не является каталогом: {}".format(path), file=sys.stderr)
        sys.exit(1)

    # ИСПРАВЛЕНО
    print("Сканирование каталога {}...".format(path), file=sys.stderr)
    for root, dirs, files in os.walk(path):
        for name in files:
            filepath = os.path.join(root, name)
            info = get_file_info(filepath)
            if info:
                results.append(info)
        for name in dirs:
            filepath = os.path.join(root, name)
            info = get_file_info(filepath)
            if info:
                results.append(info)

    return results


def filter_results(results, world_writable_only, executable_only):
    """
    Фильтрует результаты согласно флагам командной строки.
    """
    filtered = results
    if world_writable_only:
        filtered = [r for r in filtered if r['is_world_writable']]
    if executable_only:
        filtered = [r for r in filtered if r['is_executable']]
    return filtered


def export_report(data, export_path):
    """
    Экспортирует отчет в файл формата .txt, .csv или .json в зависимости от расширения.
    """
    ext = os.path.splitext(export_path)[1].lower()

    try:
        if ext == '.json':
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)

        elif ext == '.csv':
            if not data:
                with open(export_path, 'w', encoding='utf-8') as f:
                    pass
                return
            fieldnames = data[0].keys()
            with open(export_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)

        elif ext == '.txt':
            with open(export_path, 'w', encoding='utf-8') as f:
                # ИСПРАВЛЕНО
                f.write(
                    "Отчет о правах доступа. Сформирован: {}\n".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                f.write("=" * 100 + "\n")
                fmt = "{:<10} {:<8} {:<15} {:<15} {:<50} {:<10}\n"
                f.write(fmt.format("Права", "8-ричн.", "Владелец", "Группа", "Путь", "Статус"))
                f.write("-" * 100 + "\n")
                for item in data:
                    status = ""
                    if item['is_777']:
                        status += "777!"
                    elif item['is_world_writable']:
                        status += "WW!"
                    if item['is_executable'] and not item['is_777'] and not item['is_world_writable']: status += "EXE"

                    f.write(fmt.format(
                        item['permissions'],
                        item['octal'],
                        item['owner'],
                        item['group'],
                        item['path'],
                        status
                    ))
        else:
            # ИСПРАВЛЕНО
            print("[ОШИБКА] Неподдерживаемый формат экспорта: {}. Используйте .txt, .csv или .json".format(ext),
                  file=sys.stderr)
            sys.exit(1)

        # ИСПРАВЛЕНО
        print("[ИНФО] Отчет успешно сохранен в: {}".format(export_path), file=sys.stderr)

    except IOError as e:
        # ИСПРАВЛЕНО
        print("[ОШИБКА] Не удалось записать файл отчета: {}".format(e), file=sys.stderr)
        sys.exit(1)


def print_console(data):
    """
    Выводит результаты на экран в удобочитаемом виде.
    """
    if not data:
        print("Объекты, соответствующие критериям, не найдены.")
        return

    fmt = "{:<12} {:<10} {:<15} {:<15} {:<10} {}"
    print(fmt.format("Права", "8-ричн.", "Владелец", "Группа", "Статус", "Путь"))
    print("-" * 110)

    for item in data:
        status = ""
        if item['is_777']:
            status = "777/ОПАСНО"
        elif item['is_world_writable']:
            status = "WW/ОПАСНО"
        elif item['is_executable']:
            status = "ИСПОЛН."

        print(fmt.format(
            item['permissions'],
            item['octal'],
            item['owner'],
            item['group'],
            status,
            item['path']
        ))


def main():
    parser = argparse.ArgumentParser(
        description="Утилита анализа прав доступа к файлам (Astra Linux). Выявляет потенциально небезопасные объекты.",
        epilog="Пример: ./perm-check --path /opt/project --world-writable --export report.csv"
    )
    parser.add_argument('--path', type=str, default='.',
                        help='Путь к каталогу для сканирования (по умолчанию: текущий каталог)')
    parser.add_argument('--world-writable', action='store_true',
                        help='Показать только объекты, доступные на запись для всех (включая 777)')
    parser.add_argument('--executable', action='store_true',
                        help='Показать только исполняемые файлы')
    parser.add_argument('--export', type=str, metavar='FILE',
                        help='Экспортировать отчет в файл (.txt, .csv, .json)')

    args = parser.parse_args()

    results = scan_directory(args.path)
    filtered = filter_results(results, args.world_writable, args.executable)

    if args.export:
        export_report(filtered, args.export)
    else:
        print_console(filtered)


if __name__ == '__main__':
    main()