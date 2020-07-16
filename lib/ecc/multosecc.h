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

#ifndef __RKVAC_PROTOCOL_MULTOS_ECC_H_
#define __RKVAC_PROTOCOL_MULTOS_ECC_H_

#ifdef __cplusplus
extern "C"
{
#endif

// SmartDeck inline assembly support
#include <melasm.h>
// SmartDeck arbitrary sized number support
#include <multosarith.h>

#define __PRIM_MODULAR_REDUCTION                    0xC3
#define __PRIM_MODULAR_INVERSE                      0xD0
#define __PRIM_MODULAR_MULTIPLICATION               0xC2

#define __PRIM_ECC_INVERSE                          0xD3
#define __PRIM_ECC_ADDITION                         0xD0
#define __PRIM_ECC_SCALAR_MULTIPLICATION            0xD4

/**
 * Subtraction
 *
 * This primitive calculates the subtraction of two values.
 */
#define __subtraction(result, number1, number2, length)                 \
{                                                                       \
    __push(result);                                                     \
    __push(BLOCKCAST(length)(__typechk(unsigned char *, number1)));     \
    __push(BLOCKCAST(length)(__typechk(unsigned char *, number2)));     \
    __code(SUBN, length);                                               \
    __code(POPN, length);                                               \
    __code(STOREI, length);                                             \
}

/**
 * Modular Reduction
 *
 * This primitive reduces an operand with respect to a modulus.
 */
#define __modular_reduction(operand, operand_length, modulus, modulus_length)   \
{                                                                               \
    __push(__typechk(unsigned int, operand_length));                            \
    __push(__typechk(unsigned int, modulus_length));                            \
    __push(__typechk(unsigned char *, operand));                                \
    __push(__typechk(unsigned char *, modulus));                                \
    __code(PRIM, __PRIM_MODULAR_REDUCTION);                                     \
}

/**
 * Modular Inverse
 *
 * This primitive calculates the modular inverse of a value. A modular inverse of
 * an integer b (modulo m) is the integer b^-1 such that b·b^-1 = 1 (mod m).
 */
#define __modular_inverse(result, operand, operand_length, modulus, modulus_length)     \
{                                                                                       \
    __push(__typechk(unsigned int, modulus_length));                                    \
    __push(__typechk(unsigned char *, modulus));                                        \
    __push(__typechk(unsigned int, operand_length));                                    \
    __push(__typechk(unsigned char *, operand));                                        \
    __push(__typechk(unsigned char *, result));                                         \
    __code(PRIM, __PRIM_MODULAR_INVERSE, 0x01);                                         \
}

/**
 * Modular Addition
 *
 * This primitive calculates the modular addition of two values.
 */
#define __modular_addition(result, number1, number2, length)        \
{                                                                   \
  __code(PUSHZ, 1);                                                 \
  __push(BLOCKCAST(length)(__typechk(unsigned char *, number1)));   \
  __code(PUSHZ, 1);                                                 \
  __push(BLOCKCAST(length)(__typechk(unsigned char *, number2)));   \
  __code(ADDN, length + 1);                                         \
  __code(POPN, length + 1);                                         \
  __code(STORE, __typechk(unsigned char *, result), length + 1);    \
}

/**
 * Modular Subtraction
 *
 * This primitive calculates the modular subtraction of two values.
 */
#define __modular_subtraction(result, number1, number2, length, modulus)    \
{                                                                           \
    __push(result);                                                         \
    __push(BLOCKCAST(length)(__typechk(unsigned char *, number1)));         \
    __push(BLOCKCAST(length)(__typechk(unsigned char *, number2)));         \
    __code(SUBN, length);                                                   \
    __code(POPN, length);                                                   \
    __push(BLOCKCAST(length)(__typechk(unsigned char *, modulus)));         \
    __code(ADDN, length);                                                   \
    __code(POPN, length);                                                   \
    __code(STOREI, length);                                                 \
}

/**
 * Modular Multiplication
 *
 * This primitive multiples two operands and reduces the result of the multiplication
 * modulo a given modulus, that is (operand1 * operand2) mod modulus. The result
 * overwrites the first operand.
 */
#define __modular_multiplication(operand1, operand2, modulus, modulus_length)   \
{                                                                               \
    __push(__typechk(unsigned int, modulus_length));                            \
    __push(__typechk(unsigned char *, operand1));                               \
    __push(__typechk(unsigned char *, operand2));                               \
    __push(__typechk(unsigned char *, modulus));                                \
    __code(PRIM, __PRIM_MODULAR_MULTIPLICATION);                                \
}

/**
 * ECC Inverse
 *
 * This primitive calculates the inverse (negation) of a point on an elliptic
 * curve. The output point will be written in the same representation (affine
 * or projective) as the input point.
 */
#define __ecc_inverse(elliptic_curve_domain, result, ec_point)  \
{                                                               \
    __push(__typechk(unsigned char *, elliptic_curve_domain));  \
    __push(__typechk(unsigned char *, ec_point));               \
    __push(__typechk(unsigned char *, result));                 \
    __code(PRIM, __PRIM_ECC_INVERSE);                           \
}

/**
 * ECC Addition
 *
 * This primitive calculates the point that is the result of the addition of two
 * points on the elliptic curve specified by the domain parameters. If the two
 * points are equal the primitive calculates the double of the point.
 *
 * Both input points must be in the same representation, affine or projective, and
 * the result is produced in that same representation. If the input representation
 * is different from that of the application, then calling the primitive results
 * in an abend.
 */
#define __ecc_addition(elliptic_curve_domain, result, ec_point1, ec_point2)     \
{                                                                               \
    __push(__typechk(unsigned char *, elliptic_curve_domain));                  \
    __push(__typechk(unsigned char *, ec_point1));                              \
    __push(__typechk(unsigned char *, ec_point2));                              \
    __push(__typechk(unsigned char *, result));                                 \
    __code(PRIM, __PRIM_ECC_ADDITION);                                          \
}

/**
 * ECC Scalar Multiplication
 *
 * This primitive performs a scalar multiplication of a point on the elliptic curve specified
 * by the supplied domain parameters by the specified unsigned integer multiplier which is one
 * byte longer than the length specified in the domain parameters. The result, a point on the
 * curve, is written at the specified segment address in the same representation as the input
 * point.
 */
#define __ecc_scalar_multiplication(elliptic_curve_domain, result, ec_point, multiplier)    \
{                                                                                           \
    __push(__typechk(unsigned char *, elliptic_curve_domain));                              \
    __push(__typechk(unsigned char *, ec_point));                                           \
    __push(__typechk(unsigned char *, multiplier));                                         \
    __push(__typechk(unsigned char *, result));                                             \
    __code(PRIM, __PRIM_ECC_SCALAR_MULTIPLICATION);                                         \
}

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_MULTOS_ECC_H_ */
