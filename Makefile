# 
#  Makefile for https://github.com/mmaraya/port-mirroring
# 
#  Copyright (c) 2015 Mike Maraya <mike[dot]maraya[at]gmail[dot]com>
#  All rights reserved.
# 
#  This file is subject to the terms and conditions defined in
#  https://github.com/mmaraya/port-mirroring/blob/master/LICENSE,
#  which is part of this software package.
# 

SHELL     := /bin/sh
PROGRAM   := port-mirroring 
SRC_DIR   := src
OBJ_DIR   := obj
BIN_DIR   := bin
INC_DIR   := include
C_FILES   := $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES := $(addprefix $(OBJ_DIR)/,$(notdir $(C_FILES:.c=.o)))
LIB_FILES := -lpcap -lpthread
CC        := cc
CC_FLAGS  := -g -Wall -Wextra -Werror -I$(INC_DIR)
LD_FLAGS  := 

.PHONY: all clean check

all: $(BIN_DIR)/$(PROGRAM) 

$(BIN_DIR)/$(PROGRAM): $(OBJ_FILES)
	@mkdir -p $(@D)
	$(CC) $(LD_FLAGS) -o $@ $^ $(LIB_FILES)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CC_FLAGS) -c -o $@ $<

clean:
	rm -f $(BIN_DIR)/$(PROGRAM) $(OBJ_DIR)/*.o

check:
	cppcheck --enable=all -I $(INC_DIR) $(SRC_DIR)/*.c
