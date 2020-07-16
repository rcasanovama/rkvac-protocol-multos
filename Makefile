##
#
#  Copyright (C) 2020  Raul Casanova Marques
#
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
##

RM := rm -f

HCL := hcl
ALU := halugen

CNF_DIR := config
INC_DIR := include
LIB_DIR := lib

SRCS := main.c
OBJS := $(SRCS:%.c=%.hzo)

OUT_HZX := rkvac-multos.hzx
OUT_ALU := rkvac-multos.alu

all: clean rkvac-multos.alu

rkvac-multos.alu: rkvac-multos.hzx
	$(ALU) $<

rkvac-multos.hzx: $(OBJS)
	$(HCL) -g -o $@ $(OBJS)

%.hzo: %.c
	$(HCL) -I$(CNF_DIR) -I$(INC_DIR) -I$(LIB_DIR) -c -g -o $@ $<

clean:
	$(RM) $(OBJS) $(OUT_HZX) $(OUT_ALU)
