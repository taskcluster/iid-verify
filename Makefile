BENCH_ITER=10
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

.PHONY: test
test: memtests ctests shell-tests
	./test-cmdline.sh
