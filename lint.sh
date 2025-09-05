#!/bin/bash

echo "Running code quality checks..."
echo

echo "=== Ruff Linter ==="
ruff check app.py --fix
if [ $? -eq 0 ]; then
    echo "✅ Ruff checks passed"
else
    echo "❌ Ruff checks failed"
    exit 1
fi

echo
echo "=== MyPy Type Checker ==="
mypy app.py
if [ $? -eq 0 ]; then
    echo "✅ MyPy checks passed"
else
    echo "❌ MyPy checks failed"
    exit 1
fi

echo
echo "✅ All checks passed!"