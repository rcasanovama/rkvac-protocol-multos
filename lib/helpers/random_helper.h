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

#ifndef __RKVAC_PROTOCOL_RANDOM_HELPER_H_
#define __RKVAC_PROTOCOL_RANDOM_HELPER_H_

#ifdef __cplusplus
extern "C"
{
#endif

// SmartDeck inline assembly support
#include <melasm.h>

#define __PRIM_GET_RANDOM_NUMBER                0xC4

#define __set_by_csprng(address)                \
{                                               \
      __push(address);                          \
      __code(PRIM, __PRIM_GET_RANDOM_NUMBER);   \
      __code(PRIM, __PRIM_GET_RANDOM_NUMBER);   \
      __code(PRIM, __PRIM_GET_RANDOM_NUMBER);   \
      __code(PRIM, __PRIM_GET_RANDOM_NUMBER);   \
      __code(STOREI, 32);                       \
}

/**
 * Writes random bytes to address by cryptographically secure
 * pseudo random number generator.
 *
 * @param address pointer to where the random number will be written
 */
extern void set_by_csprng(unsigned char *address);

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_RANDOM_HELPER_H_ */
