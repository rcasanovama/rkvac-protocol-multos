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

#ifndef __RKVAC_PROTOCOL_MODEL_ISSUER_H_
#define __RKVAC_PROTOCOL_MODEL_ISSUER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "config/config.h"

#include "types.h"

typedef struct
{
    elliptic_curve_point_t sigma; // sigma
    elliptic_curve_point_t revocation_sigma; // sigma x(r)
    elliptic_curve_point_t attribute_sigmas[USER_MAX_NUM_ATTRIBUTES]; // sigmas x(1)...x(n-1)
} issuer_signature_t;

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_MODEL_ISSUER_H_ */
