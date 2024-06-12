all: hello ckp run_hello ckp_with_pid restore

hello: runners/hello.c
	gcc runners/hello.c -o hello

ckp: checkpoint.c
	gcc -o checkpoint checkpoint.c

restore: restore.c
	gcc -o restore restore.c

run_hello: hello
	./hello & echo $$! > hello_pid.txt

ckp_with_pid: ckp
	sleep 5
	@sudo ./checkpoint `cat hello_pid.txt`

clean:
	@if [ -f hello_pid.txt ]; then \
		PID=`cat hello_pid.txt`; \
		if kill $$PID > /dev/null 2>&1; then \
			: ; \
		else \
			: ; \
		fi; \
		rm -f hello_pid.txt; \
	fi
	rm -f hello
	rm -f restore
	rm -f checkpoint
	rm -f register_dump.bin
	rm -f layout.bin
	rm -f memory_dump.bin

kill:
	@if [ -f hello_pid.txt ]; then \
		PID=`cat hello_pid.txt`; \
		if kill $$PID > /dev/null 2>&1; then \
			: ; \
		else \
			: ; \
		fi; \
	fi