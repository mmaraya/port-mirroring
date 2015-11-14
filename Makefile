# 
#  The MIT License (MIT)
# 
#  Copyright (c) 2015 Mike Maraya <mike[dot]maraya[at]gmail[dot]com>
# 
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
# 
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
# 
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
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
CC_FLAGS  := -g -Wall -Wextra -I$(INC_DIR)
LD_FLAGS  := 

.PHONY: all clean test

all: $(BIN_DIR)/$(PROGRAM)

$(BIN_DIR)/$(PROGRAM): $(OBJ_FILES)
	@mkdir -p $(@D)
	$(CC) $(LD_FLAGS) -o $@ $^ $(LIB_FILES)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CC_FLAGS) -c -o $@ $<

clean:
	rm -f $(BIN_DIR)/$(PROGRAM) $(OBJ_DIR)/*.o

