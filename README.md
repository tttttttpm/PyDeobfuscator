# PyDeobfuscator
Деобфускатор модулей Python 3, основанный на AST-трансформерах.

## Как пользоваться 

Просканировать один файл:

```bash
python3 deob.py -f path/to/file.py
```

Рекурсивно просканировать директорию:

```bash
python3 deob.py -d /path/to/dir
```

Просканировать модуль:

```bash
python3 deob.py -m module_name
```

Также можно использовать флаг -s, чтобы не сохранять деобфсуцированные файлы:

```bash
python3 deob.py -s -d /path/to/dir
```
