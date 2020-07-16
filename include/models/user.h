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

#ifndef __RKVAC_PROTOCOL_MODEL_USER_H_
#define __RKVAC_PROTOCOL_MODEL_USER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "config/config.h"

#include "types.h"

typedef struct
{
    uint8_t buffer[USER_MAX_ID_LENGTH];
} user_identifier_t;

typedef struct
{
    uint8_t num_attributes;
    elliptic_curve_fr_t attributes[USER_MAX_NUM_ATTRIBUTES];
} user_attributes_t;

typedef struct
{
    elliptic_curve_point_t sigma_hat;
    elliptic_curve_point_t sigma_hat_e1;
    elliptic_curve_point_t sigma_hat_e2;
    elliptic_curve_point_t sigma_minus_e1;
    elliptic_curve_point_t sigma_minus_e2;
    elliptic_curve_point_t pseudonym; // C
} user_credential_t;

typedef struct
{
    elliptic_curve_point_t t_verify; // 65B
    elliptic_curve_point_t t_revoke; // 65B
    elliptic_curve_point_t t_sig;  // 65B
    elliptic_curve_point_t t_sig1; // 65B
    elliptic_curve_point_t t_sig2; // 65B
} user_t_values_t;

typedef struct
{
    user_t_values_t user_t_values;
    user_credential_t user_credential;
    elliptic_curve_fr_t nonce;
} user_hash_data_t;

typedef struct
{
    uint8_t e[SHA_DIGEST_LENGTH];
    elliptic_curve_multiplier_t s_v;
    elliptic_curve_multiplier_t s_i;
    elliptic_curve_fr_t s_e1;
    elliptic_curve_fr_t s_e2;
    elliptic_curve_fr_t s_mr;
    elliptic_curve_fr_t s_mz[USER_MAX_NUM_ATTRIBUTES]; // s_mz non-disclosed attributes
} user_pi_t;

#ifdef __cplusplus
}
#endif

#endif /* __RKVAC_PROTOCOL_MODEL_USER_H_ */
