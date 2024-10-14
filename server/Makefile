# SPDX-License-Identifier: MIT
NAME    = multiplay
CC      = g++
PROF    = -O3
C_FLAGS = -std=c++17 -Wall -Wextra -pedantic-errors -Wconversion \
          -Wno-unused-parameter -fmax-errors=5
L_FLAGS = -lm -lstdc++
SRC_DIR = src
OBJ_DIR = obj
DEFINES =

SRC_FILES := $(wildcard $(SRC_DIR)/*.cpp)
O_FILES   := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRC_FILES))

OUT = ./$(NAME)

all:
	@$(MAKE) make_dynamic -s

debug:
	@$(MAKE) make_debug -s

make_dynamic: $(O_FILES)
	@printf "\033[1;33mMaking \033[37m   ...."
	$(CC) -o $(OUT) $(O_FILES) $(L_FLAGS)
	@printf "\033[1;32m Optimized %s done!\033[0m\n" $(NAME)

make_debug: PROF = -O0 -g -rdynamic
make_debug: DEFINES = -DMULTIPLAY_DEBUG
make_debug: $(O_FILES)
	@printf "\033[1;33mMaking \033[37m   ...."
	$(CC) -o $(OUT) $(O_FILES) $(L_FLAGS)
	@printf "\033[1;32m Debug %s done!\033[0m\n" $(NAME)

PRINT_FMT1 = "\033[1m\033[31mCompiling \033[37m....\033[34m %-20s"
PRINT_FMT2 = "\t\033[33m%6s\033[31m lines\033[0m \n"
PRINT_FMT  = $(PRINT_FMT1)$(PRINT_FMT2)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@printf $(PRINT_FMT) $*.cpp "`wc -l $(SRC_DIR)/$*.cpp | cut -f1 -d' '`"
	@$(CC) $< $(C_FLAGS) $(PROF) $(DEFINES) -c -o $@

clean:
	@printf "\033[1;36mCleaning \033[37m ...."
	@rm -f $(O_FILES) $(OUT)
	@printf "\033[1;37m Binaries of $(NAME) cleaned!\033[0m\n"
