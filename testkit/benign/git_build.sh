#!/usr/bin/env bash
# git init + commit of a small C project, a local `git clone`, then make.
source "$(dirname "$0")/_common.sh"
if [ "$step" = setup ]; then
    rm -rf src clone; mkdir -p src && cd src
    for i in $(seq 1 20); do printf 'int f%d(int x) { return x + %d; }\n' "$i" "$i" > "f$i.c"; done
    printf 'int f1(int);\nint main(void) { return f1(0) == 1 ? 0 : 1; }\n' > main.c
    printf 'OBJ := $(patsubst %%.c,%%.o,$(wildcard *.c))\nprog: $(OBJ)\n\t$(CC) -o $@ $^\nclean:\n\trm -f *.o prog\n' > Makefile
    git init -q . && git -c user.email=b@example.invalid -c user.name=benign add . && \
        git -c user.email=b@example.invalid -c user.name=benign commit -qm init
    exit 0
fi
git clone -q src clone && make -s -C clone -j2 && ./clone/prog && rm -rf clone
