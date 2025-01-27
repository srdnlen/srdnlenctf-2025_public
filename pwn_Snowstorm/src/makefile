CC = gcc
CARGS = $@.c -o $@
NO_CANARY = -fno-stack-protector
NO_PIE = -no-pie
PARTIAL_RELRO = -Wl,-z,relro
FULL_RELRO = ${PARTIAL_RELRO},-z,now

snowstorm: snowstorm.c flag.txt
	${CC} ${CARGS} ${NO_CANARY} ${NO_PIE}
