#!/usr/bin/env bash
# Python venv: create it, use its pip offline, install a local pure-Python
# package (no network), byte-compile a module tree.
source "$(dirname "$0")/_common.sh"
if [ "$step" = setup ]; then
    rm -rf venv pkg; mkdir -p pkg/benignpkg
    printf 'def hello():\n    return "hi"\n' > pkg/benignpkg/__init__.py
    exit 0
fi
python3 -m venv venv
./venv/bin/pip --version > /dev/null
# No network: copy the package into site-packages the way an offline
# install would, then import and byte-compile it.
site=$(./venv/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
cp -r pkg/benignpkg "$site/"
./venv/bin/python -c 'import benignpkg; assert benignpkg.hello() == "hi"'
./venv/bin/python -m compileall -q "$site/benignpkg"
rm -rf venv
