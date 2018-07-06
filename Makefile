BENCH_ITER=10

.PHONY: clangfmt
clangfmt:


.PHONY: memtests
memtests: src/verify.c src/tests.c
	clang -g $? -o ./$@ -Wall -Werror -lcrypto -lefence -DEXTRA_DEBUG -DBENCH_ITER=$(BENCH_ITER)
	valgrind --leak-check=full ./$@

.PHONY: ctests
ctests: src/verify.c src/tests.c
	clang -g $? -o ./$@ -Wall -Werror -lcrypto -DEXTRA_DEBUG -DBENCH_ITER=100000
	./$@

.PHONY: shell-tests
	./test-cmdline.sh

.PHONY: format
format:
	clang-format -i src/*.c src/*.h


.PHONY: test
test: format memtests ctests shell-tests
