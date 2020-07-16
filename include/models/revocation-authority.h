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

#ifndef __RKVAC_PROTOCOL_MODEL_REVOCATION_AUTHORITY_H_
#define __RKVAC_PROTOCOL_MODEL_REVOCATION_AUTHORITY_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "config/config.h"

#include "types.h"

typedef struct
{
    uint8_t k, j;

    elliptic_curve_fr_t alphas[REVOCATION_AUTHORITY_VALUE_J]; // alpha_j
    elliptic_curve_point_t alphas_mul[REVOCATION_AUTHORITY_VALUE_J]; // h_j = G1 * alpha_j

    elliptic_curve_multiplier_t randomizers[REVOCATION_AUTHORITY_VALUE_K];  // e_k
    elliptic_curve_point_t randomizers_sigma[REVOCATION_AUTHORITY_VALUE_K]; // sigma_e_k
} revocation_authority_par_t;

typedef struct
{
    elliptic_curve_fr_t mr;
    elliptic_curve_point_t sigma;
} revocation_authority_signature_t;

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_MODEL_REVOCATION_AUTHORITY_H_ */
