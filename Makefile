BENCH_ITER=10

.PHONY: clangfmt
clangfmt:


.PHONY: memtests
memtests: src/verify.c src/tests.c
	clang -g $? -o ./$@ -Wall -Wextra -Werror -lcrypto -lefence -DEXTRA_DEBUG -DBENCH_ITER=$(BENCH_ITER)
	valgrind --read-var-info=yes --track-origins=yes --leak-check=full ./$@

.PHONY: ctests
ctests: src/verify.c src/tests.c
	# Extra sanitizers
	clang -g $? -o ./$@ -Wall -Wextra -Werror -lcrypto -DVF_DEBUG=1 -DBENCH_ITER=1000 -fsanitize=undefined,integer,nullability
	./$@
	clang -g $? -o ./$@ -Wall -Wextra -Werror -lcrypto -DVF_DEBUG=1 -DBENCH_ITER=1000
	./$@
	gcc -g $? -o ./$@ -Wall -Wextra -Werror -lcrypto -DVF_DEBUG=1 -DBENCH_ITER=1000
	./$@

.PHONY: shell-tests
shell-tests:
	./test-cmdline.sh

.PHONY: format
format:
	clang-format -i src/*.c src/*.h

.PHONY: test
test: format memtests ctests shell-tests
	@echo These unit tests passed
