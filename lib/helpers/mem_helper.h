/**
 *
 *  Copyright (C) 2020  Raul Casanova Marques
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __RKVAC_PROTOCOL_MEM_HELPER_H_
#define __RKVAC_PROTOCOL_MEM_HELPER_H_

#ifdef __cplusplus
extern "C"
{
#endif

// SmartDeck inline assembly support
#include <melasm.h>

#define __PRIM_MEMORY_COPY_NA_FIXED_LENGTH          0x13
#define __PRIM_MEMORY_COMPARE_FIXED_LENGTH          0x0F
#define __PRIM_LOAD_CCR                             0x05
#define __PRIM_BIT_MANIPULATE_BYTE                  0x01

/**
 * Memory Copy Non-Atomic Fixed Length
 *
 * This primitive copies a block of bytes of a fixed length from one location
 * to another. If the byte block is copied into the static area, data item
 * protection function will be disabled if possible.
 *
 * All of the parameters are 2 bytes in size. The values DestinationAddr and
 * SourceAddr are, respectively, the locations to where and from where the data
 * is copied.
 *
 * Stack In:
 * 	DestinationAddr
 * 	SourceAddr
 * Stack Out:
 * 	{empty}
 *
 * Remarks:
 *  When copying into the static memory area with this primitive, the copying
 *  will be performed more quickly than with Memory Copy primitive as the data
 *  items are not protected.
 *
 * @param dst pointer to the destination where the content is to be copied
 * @param src pointer to the source of data to be copied
 * @param n number of bytes to copy
 */
#define __multos_memcpy_non_atomic_fixed_length(dst, src, n)    \
{                                                               \
    __push (__typechk(unsigned char *, dst));                   \
    __push (__typechk(unsigned char *, src));                   \
    __code (PRIM, __PRIM_MEMORY_COPY_NA_FIXED_LENGTH, n);       \
}

/**
 * Memory Compare Fixed Length
 *
 * This primitive is used to compare two blocks of bytes of a fixed length.
 *
 * Stack In:
 * 	Addr1
 * 	Addr2
 * Stack Out:
 * 	AddrRet
 *
 * Remarks:
 *  The Length value is specified using a single byte. Therefore, the maximum
 *  length of a block is 255 bytes.
 *
 *  The comparison performed by this primitive is based on subtraction.
 *  The second operand, the area corresponding to the address on the top of the
 *  stack, is subtracted from the first. No data is modified, but the Condition
 *  Code Register is set according to the result of the operation.
 *
 * @param s1 pointer to block of memory
 * @param s2 pointer to block of memory
 * @param n number of bytes to compare
 * @param ret return value
 */
#define __multos_memcmp_fixed_length(s1, s2, n, ret)        \
{                                                           \
    __push (__typechk(unsigned char *, s1));                \
    __push (__typechk(unsigned char *, s2));                \
    __code (PRIM, __PRIM_MEMORY_COMPARE_FIXED_LENGTH, n);   \
    __code (PRIM, __PRIM_LOAD_CCR);                         \
    __code (PRIM, __PRIM_BIT_MANIPULATE_BYTE, 0x83, 0x09);  \
    __code (STORE, __typechk(unsigned char *, ret), 1);     \
}

/**
 * CLEARN
 *
 * void multosBlockClear (const BYTE blockLength, const BYTE *block)
 *
 * This instruction sets a byte-block to zero.
 *
 * Remarks:
 *  The block_length value is specified using a single byte. Therefore, the
 *  maximum length of a block is 255 bytes.
 *
 * @param block address of the block to be cleared
 * @param len size of the block to clear
 */
#define __multos_memzero(block, len)    \
{                                       \
    __code (CLEARN, block, len);        \
}

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_MEM_HELPER_H_ */
