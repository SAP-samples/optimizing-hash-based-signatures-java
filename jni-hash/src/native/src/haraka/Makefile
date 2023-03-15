# ================================ #
#  Makefile for haraka             #
#  Lena Heimberger, Feb 2020       #
#                                  #
#  Based on the original Haraka    #
#  Makefile by Stefan Kölbl        #
# ================================ #

# which compiler?
CC=gcc

# output directories
CLASS_PATH=../bin
vpath %.class $(CLASS_PATH)

# optimization level (-Ox)
OPT=3

# debug enabled?
#DEB=-g
DEB=
LIB=-fPIC -shared -lc

# ======================================= #
# BE CAREFUL WHEN EDITING BELOW THIS LINE #
# ======================================= #
CF=-O$(OPT) -fomit-frame-pointer -funroll-all-loops -Wno-int-conversion $(DEB)

JNA_HEADERS_64=/usr/lib/jvm/java-13-openjdk-amd64/include
JNA_OS_HEADERS_64=/usr/lib/jvm/java-13-openjdk-amd64/include/linux

HARAKA_SRC=at_iaik_pq_sphincs_utils_HarakaUtils_Haraka.c

GCC_F=-march=nocona
AES_FLAGS=-maes -mssse3 -msse4.1
M32=-m32 -w $(GCC_F)
M64=-m64 $(GCC_F)

VERSION_AES=AES

.PHONY: all haraka-aes clean clean-pack clean-all pack-cl pack

all: clean haraka-aes

haraka-aes:
	$(CC) $(LIB)  $(AES_FLAGS) $(M64) $(CF) -I$(JNA_HEADERS_64) -I$(JNA_OS_HEADERS_64) $(HARAKA_SRC) -o $(CLASS_PATH)/haraka.so
clean:
	@rm -f $(CLASS_PATH)/*

clean-pack:
	@rm -f haraka.tar.bz2

clean-all: clean clean-pack

pack-cl: clean pack

pack: clean-pack
	tar --exclude-vcs  -cjf ../haraka.tar.bz2 ../`pwd | sed 's,^\(.*/\)\?\([^/]*\),\2,'`
	mv ../haraka.tar.bz2 ./
