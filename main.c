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

#pragma attribute("aid", "f0 00 00 01")
#pragma attribute("dir", "61 0d 4f 04 f0 00 00 01 50 05 72 6b 76 61 63")

// ISO codes
#include <ISO7816.h>
// SmartDeck comms support
#include <multoscomms.h>
// SmartDeck crypto support
#include <multoscrypto.h>

// Standard libraries
#include <string.h>

// ECC support
#include "ecc/multosecc.h"

#include "helpers/mem_helper.h"
#include "helpers/random_helper.h"

#include "config/config.h"

#include "models/issuer.h"
#include "models/revocation-authority.h"
#include "models/user.h"

#include "apdu.h"
#include "types.h"

/// Global values - RAM (Public memory)
#pragma melpublic
uint8_t apdu_data[APDU_L_MAX];

/// Session values - RAM (Dynamic memory)
#pragma melsession
uint8_t num_non_disclosed_attributes = 0;

elliptic_curve_multiplier_t ecm_tmp1 = {0x00}; // 33B
elliptic_curve_multiplier_t ecm_tmp2 = {0x00}; // 33B

elliptic_curve_point_t ecp_tmp = {0x04}; // 65B
elliptic_curve_point_t ecp_g1_rho_v = {0x04}; // 65B

elliptic_curve_multiplier_t i;

// rho values
elliptic_curve_multiplier_t rho = {0x00}; // 33B
elliptic_curve_multiplier_t rho_v = {0x00}; // 33B
elliptic_curve_multiplier_t rho_i = {0x00}; // 33B
elliptic_curve_multiplier_t rho_e1 = {0x00}; // 33B
elliptic_curve_multiplier_t rho_e2 = {0x00}; // 33B
elliptic_curve_multiplier_t rho_mr = {0x00}; // 33B

// hash data (t values, user credential, and nonce)
user_hash_data_t user_hash_data = {0x00};

/// Static values - EEPROM (Static memory)
#pragma melstatic
size_t offset = 0;
size_t it = 0;

// user identifier and attributes
user_identifier_t user_identifier = {
        0x02, 0x0F, 0x84, 0x31, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0x1A, 0x2B, 0x3C, 0x4D,
        0x5E, 0x6F, 0x00, 0x40, 0x00, 0xFF, 0x01
};
user_attributes_t user_attributes = {0};

// user attribute rho's
elliptic_curve_multiplier_t rho_mz[USER_MAX_NUM_ATTRIBUTES] = {0x00};

// user pi
user_pi_t user_pi = {0};

// revocation authority data
revocation_authority_par_t revocation_authority_par = {0};
revocation_authority_signature_t revocation_authority_signature = {0};
// issuer signature (sigmas)
issuer_signature_t issuer_signature = {0};

// epoch
uint8_t epoch[EPOCH_LENGTH] = {0};

uint8_t I = 0; // first pseudo-random value used to select the first randomizer
uint8_t II = 0; // second pseudo-random value used to select the second randomizer

uint8_t res = 0x00; //1B

uint8_t elliptic_curve_base_point_affine = {0x0F};
elliptic_curve_domain_t elliptic_curve_domain = {
        0x00, // Format of domain params
        0x20, // Prime length in bytes
        0x25, 0x23, 0x64, 0x82, 0x40, 0x00, 0x00, 0x01, 0xba, 0x34, 0x4d, 0x80,
        0x00, 0x00, 0x00, 0x08, 0x61, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
        0xa7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, // p
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // a
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // b
        0x25, 0x23, 0x64, 0x82, 0x40, 0x00, 0x00, 0x01, 0xBA, 0x34, 0x4D, 0x80,
        0x00, 0x00, 0x00, 0x08, 0x61, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
        0xA7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, //Gx
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, //Gy
        0x25, 0x23, 0x64, 0x82, 0x40, 0x00, 0x00, 0x01, 0xba, 0x34, 0x4d, 0x80,
        0x00, 0x00, 0x00, 0x07, 0xff, 0x9f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x10,
        0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, // N
        0x01 // H
}; // mcl 256bit

void main(void)
{
    if (CLA != CLA_APPLICATION)
    {
        ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
    }

    switch (INS)
    {
        case INS_GET_USER_IDENTIFIER:
        {
            if (!CheckCase(2))
            {
                ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
                break;
            }

            // copy user identifier
            memcpy(apdu_data, (const void *) &user_identifier, USER_MAX_ID_LENGTH);

            ExitSWLa(ISO7816_SW_NO_ERROR, USER_MAX_ID_LENGTH);
            break;
        }

        case INS_SET_REVOCATION_AUTHORITY_DATA:
        {
            if (!CheckCase(3))
            {
                ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
                break;
            }

            if (P1 == 0x01) // receive revocation authority data (mr, sigma) at the beginning
            {
                memcpy((void *) &revocation_authority_signature, apdu_data, sizeof(revocation_authority_signature_t));
                offset = 0;
            }
            else // receive revocation authority parameters in raw format
            {
                memcpy((void *) ((uint8_t *) &revocation_authority_par + offset), apdu_data, (size_t) Lc);
                offset += (size_t) Lc;
            }

            // custom sw to indicate that more data is expected
            ExitSW(P1 < P2 ? CUSTOM_SW_EXPECTED_ADDITIONAL_DATA : ISO7816_SW_NO_ERROR);
            break;
        }

        case INS_SET_USER_ATTRIBUTES:
        {
            if (!CheckCase(3))
            {
                ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
                break;
            }

            if (P1 == 0x01)
            {
                offset = 0;
            }

            memcpy((void *) ((uint8_t *) &user_attributes + offset), apdu_data, (size_t) Lc);
            offset += (size_t) Lc;

            // custom sw to indicate that more data is expected
            ExitSW(P1 < P2 ? CUSTOM_SW_EXPECTED_ADDITIONAL_DATA : ISO7816_SW_NO_ERROR);
            break;
        }

        case INS_GET_USER_IDENTIFIER_ATTRIBUTES:
        {
            if (!CheckCase(2))
            {
                ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
                break;
            }

            if (P1 == 0x01) // send user identifier, revocation authority data (mr, sigma) and num_attributes at the beginning
            {
                memcpy(apdu_data, (const void *) &user_identifier, USER_MAX_ID_LENGTH); // user identifier
                memcpy(&apdu_data[USER_MAX_ID_LENGTH], (const void *) &revocation_authority_signature, sizeof(revocation_authority_signature_t)); // revocation_authority_signature

                apdu_data[USER_MAX_ID_LENGTH + sizeof(revocation_authority_signature_t)] = user_attributes.num_attributes; // num_attributes
                offset = 0;

                SetLa(sizeof(user_identifier_t) + sizeof(revocation_authority_signature_t) + sizeof(uint8_t)); // user_identifier + revocation_authority_signature + num_attributes
            }
            else // send user attributes (the issuer calculates how much data remains to be received)
            {
                memcpy(apdu_data, (const void *) ((uint8_t *) &user_attributes.attributes + offset), (size_t) Le);
                offset += (size_t) Le;

                SetLa(Le);
            }

            /// TODO: fix the error with ExitSWLa!
            ExitSW(offset < user_attributes.num_attributes * sizeof(elliptic_curve_fr_t) ? CUSTOM_SW_EXPECTED_ADDITIONAL_DATA : ISO7816_SW_NO_ERROR);
            break;
        }

        case INS_SET_ISSUER_SIGNATURES:
        {
            if (!CheckCase(3))
            {
                ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
                break;
            }

            if (P1 == 0x01)
            {
                offset = 0;
            }

            memcpy((void *) ((uint8_t *) &issuer_signature + offset), apdu_data, (size_t) Lc);
            offset += (size_t) Lc;

            // custom sw to indicate that more data is expected
            ExitSW(P1 < P2 ? CUSTOM_SW_EXPECTED_ADDITIONAL_DATA : ISO7816_SW_NO_ERROR);
            break;
        }

        case INS_COMPUTE_PROOF_OF_KNOWLEDGE:
        {
            if (!CheckCase(3))
            {
                ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
                break;
            }

            /*
             * IMPORTANT!
             *
             * The attributes are disclosed from the end to the beginning,
             * i.e., if a user has 4 attributes and the verifier wants to
             * disclose 2, the disclosed attributes will be the 3rd and 4th,
             * keeping hidden the 1st and 2nd.
             *
             * +---+---+---+---+
             * | 1 | 2 | 3 | 4 |
             * +---+---+---+---+
             * | H | H | D | D |
             * +---+---+---+---+
             */
            num_non_disclosed_attributes = P1; // num_non_disclosed_attributes
            __multos_memcpy_non_atomic_fixed_length((void *) &user_hash_data.nonce, apdu_data, NONCE_LENGTH); // nonce
            if (memcmp(epoch, &apdu_data[NONCE_LENGTH], EPOCH_LENGTH) != 0)
            {
                __multos_memcpy_non_atomic_fixed_length((void *) &epoch, &apdu_data[NONCE_LENGTH], EPOCH_LENGTH); // epoch
                // I, II
            }


            /// i = alpha1·e1 + alpha2·e2
            __multos_memcpy_non_atomic_fixed_length((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &revocation_authority_par.randomizers[I].ecm, EC_SIZE); // ecm_tmp1 = e1
            __multos_memcpy_non_atomic_fixed_length((uint8_t *) &ecm_tmp2.ecm, (uint8_t *) &revocation_authority_par.randomizers[II].ecm, EC_SIZE); // ecm_tmp2 = e2
            __modular_multiplication((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &revocation_authority_par.alphas[0], (uint8_t *) &elliptic_curve_domain.N, EC_SIZE); // ecp_tmp1 = ecp_tmp1·alpha1
            __modular_multiplication((uint8_t *) &ecm_tmp2.ecm, (uint8_t *) &revocation_authority_par.alphas[1], (uint8_t *) &elliptic_curve_domain.N, EC_SIZE); // ecp_tmp2 = ecp_tmp2·alpha2
            __modular_addition((uint8_t *) &i, (uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &ecm_tmp2.ecm, EC_SIZE); // i = ecp_tmp1 + ecp_tmp2
            __modular_reduction((uint8_t *) &i, EC_SIZE + 1, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);


            // H(epoch)
            __multos_memzero((uint8_t *) &ecm_tmp2, 1 + SHA_DIGEST_PADDING);
            SHA1(EPOCH_LENGTH, (uint8_t *) &ecm_tmp2.ecm + SHA_DIGEST_PADDING, (uint8_t *) &epoch); // ecm_tmp2 = SHA1(epoch)

            /// C = (1 / i - mr + H(epoch)) * G1
            __multos_memcmp_fixed_length((uint8_t *) &revocation_authority_signature.mr, (uint8_t *) &i.ecm, EC_SIZE, (uint8_t *) &res);
            if (res == 0x08)
            {
                __subtraction((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &i.ecm, (uint8_t *) &revocation_authority_signature.mr, EC_SIZE);
            }
            else
            {
                __modular_subtraction((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &i.ecm, (uint8_t *) &revocation_authority_signature.mr, EC_SIZE, (uint8_t *) &elliptic_curve_domain.N);
            } // ecm_tmp1 = i - mr

            __modular_addition((uint8_t *) &ecm_tmp1, (uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &ecm_tmp2.ecm, EC_SIZE); // ecm_tmp1 = ecm_tmp1 + ecm_tmp2
            __modular_reduction((uint8_t *) &ecm_tmp1, EC_SIZE + 1, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);
            __modular_inverse((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &ecm_tmp1.ecm, EC_SIZE, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);

            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_credential.pseudonym, (uint8_t *) &elliptic_curve_base_point_affine, (uint8_t *) &ecm_tmp1);
            user_hash_data.user_credential.pseudonym.form = 0x04;


            /// rho random numbers
            // rho
            set_by_csprng((uint8_t *) &rho.ecm);

            // rho_v
            set_by_csprng((uint8_t *) &rho_v.ecm);

            // rho_i
            set_by_csprng((uint8_t *) &rho_i.ecm);

            // rho_e1
            set_by_csprng((uint8_t *) &rho_e1.ecm);

            // rho_e2
            set_by_csprng((uint8_t *) &rho_e2.ecm);

            // rho_mr
            set_by_csprng((uint8_t *) &rho_mr.ecm);

            // rho_mz non-disclosed attributes
            for (it = 0; it < num_non_disclosed_attributes; it++)
            {
                set_by_csprng((uint8_t *) &rho_mz[it].ecm);
            }


            /// signatures
            // sigma_hat
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_credential.sigma_hat, (uint8_t *) &issuer_signature.sigma, (uint8_t *) &rho);

            // sigma_hat_e1
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_credential.sigma_hat_e1, (uint8_t *) &revocation_authority_par.randomizers_sigma[I], (uint8_t *) &rho);

            // sigma_hat_e2
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_credential.sigma_hat_e2, (uint8_t *) &revocation_authority_par.randomizers_sigma[II], (uint8_t *) &rho);

            // ecp_tmp = G1·rho
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &ecp_tmp, (uint8_t *) &elliptic_curve_base_point_affine, (uint8_t *) &rho);
            ecp_tmp.form = 0x04;

            // sigma_minus_e1
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_credential.sigma_minus_e1, (uint8_t *) &user_hash_data.user_credential.sigma_hat_e1, (uint8_t *) &revocation_authority_par.randomizers[I]); // sigma_minus_e1 = sigma_hat_e1·e1
            __ecc_inverse((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_credential.sigma_minus_e1, (uint8_t *) &user_hash_data.user_credential.sigma_minus_e1); // sigma_minus_e1 = inv(sigma_minus_e1)
            __ecc_addition((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_credential.sigma_minus_e1, (uint8_t *) &user_hash_data.user_credential.sigma_minus_e1, (uint8_t *) &ecp_tmp); // sigma_minus_e1 = sigma_minus_e1 + (G1·rho)

            // sigma_minus_e2
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_credential.sigma_minus_e2, (uint8_t *) &user_hash_data.user_credential.sigma_hat_e2, (uint8_t *) &revocation_authority_par.randomizers[II]); // sigma_minus_e2 = sigma_hat_e2·e2
            __ecc_inverse((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_credential.sigma_minus_e2, (uint8_t *) &user_hash_data.user_credential.sigma_minus_e2); // sigma_minus_e2 = inv(sigma_minus_e2)
            __ecc_addition((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_credential.sigma_minus_e2, (uint8_t *) &user_hash_data.user_credential.sigma_minus_e2, (uint8_t *) &ecp_tmp); // sigma_minus_e2 = sigma_minus_e2 + (G1·rho)


            /// t values
            // ecp_g1_rho_v = G1·rho_v
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &ecp_g1_rho_v, (uint8_t *) &elliptic_curve_base_point_affine, (uint8_t *) &rho_v);
            ecp_g1_rho_v.form = 0x04;

            // t_verify
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_verify, (uint8_t *) &issuer_signature.revocation_sigma, (uint8_t *) &rho_mr); // t_verify = revocation_sigma·rho_mr
            for (it = 0; it < num_non_disclosed_attributes; it++)
            {
                __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &ecp_tmp, (uint8_t *) &issuer_signature.attribute_sigmas[it], (uint8_t *) &rho_mz[it]); // ecp_tmp = attribute_sigmas(it)·rho_mz(it)
                __ecc_addition((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_verify, (uint8_t *) &user_hash_data.user_t_values.t_verify, (uint8_t *) &ecp_tmp); // t_verify = t_verify + ecp_tmp
            }
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_verify, (uint8_t *) &user_hash_data.user_t_values.t_verify, (uint8_t *) &rho); // t_verify = t_verify·rho
            __ecc_addition((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_verify, (uint8_t *) &ecp_g1_rho_v, (uint8_t *) &user_hash_data.user_t_values.t_verify); // t_verify = ecp_g1_rho_v + t_verify

            // t_revoke
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_revoke, (uint8_t *) &user_hash_data.user_credential.pseudonym, (uint8_t *) &rho_mr);
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &ecp_tmp, (uint8_t *) &user_hash_data.user_credential.pseudonym, (uint8_t *) &rho_i);
            __ecc_addition((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_revoke, (uint8_t *) &user_hash_data.user_t_values.t_revoke, (uint8_t *) &ecp_tmp);

            // t_sig
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_sig, (uint8_t *) &elliptic_curve_base_point_affine, (uint8_t *) &rho_i);
            user_hash_data.user_t_values.t_sig.form = 0x04;
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &ecp_tmp, (uint8_t *) &revocation_authority_par.alphas_mul[0], (uint8_t *) &rho_e1);
            __ecc_addition((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_sig, (uint8_t *) &user_hash_data.user_t_values.t_sig, (uint8_t *) &ecp_tmp);
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &ecp_tmp, (uint8_t *) &revocation_authority_par.alphas_mul[1], (uint8_t *) &rho_e2);
            __ecc_addition((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_sig, (uint8_t *) &user_hash_data.user_t_values.t_sig, (uint8_t *) &ecp_tmp);

            // t_sig1
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_sig1, (uint8_t *) &user_hash_data.user_credential.sigma_hat_e1, (uint8_t *) &rho_e1);
            __ecc_addition((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_sig1, (uint8_t *) &ecp_g1_rho_v, (uint8_t *) &user_hash_data.user_t_values.t_sig1);

            // t_sig2
            __ecc_scalar_multiplication((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_sig2, (uint8_t *) &user_hash_data.user_credential.sigma_hat_e2, (uint8_t *) &rho_e2);
            __ecc_addition((uint8_t *) &elliptic_curve_domain, (uint8_t *) &user_hash_data.user_t_values.t_sig2, (uint8_t *) &ecp_g1_rho_v, (uint8_t *) &user_hash_data.user_t_values.t_sig2);


            /// e <-- H(...)
            SHA1(sizeof(user_hash_data_t), (uint8_t *) &user_pi.e, (uint8_t *) &user_hash_data);


            /// s values
            // s_v
            __multos_memzero((uint8_t *) &ecm_tmp1.ecm, SHA_DIGEST_PADDING);
            __multos_memcpy_non_atomic_fixed_length((uint8_t *) &ecm_tmp1.ecm + SHA_DIGEST_PADDING, (uint8_t *) &user_pi.e, SHA_DIGEST_LENGTH);
            __modular_multiplication((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &rho.ecm, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);
            __modular_addition((uint8_t *) &user_pi.s_v, (uint8_t *) &rho_v.ecm, (uint8_t *) &ecm_tmp1.ecm, EC_SIZE);
            __modular_reduction((uint8_t *) &user_pi.s_v, EC_SIZE + 1, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);

            // s_i
            __multos_memzero((uint8_t *) &ecm_tmp1.ecm, SHA_DIGEST_PADDING);
            __multos_memcpy_non_atomic_fixed_length((uint8_t *) &ecm_tmp1.ecm + SHA_DIGEST_PADDING, (uint8_t *) &user_pi.e, SHA_DIGEST_LENGTH);
            __modular_multiplication((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &i.ecm, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);
            __modular_addition((uint8_t *) &user_pi.s_i, (uint8_t *) &rho_i.ecm, (uint8_t *) &ecm_tmp1.ecm, EC_SIZE);
            __modular_reduction((uint8_t *) &user_pi.s_i, EC_SIZE + 1, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);

            // s_e1
            __multos_memzero((uint8_t *) &ecm_tmp1.ecm, SHA_DIGEST_PADDING);
            __multos_memcpy_non_atomic_fixed_length((uint8_t *) &ecm_tmp1.ecm + SHA_DIGEST_PADDING, (uint8_t *) &user_pi.e, SHA_DIGEST_LENGTH);
            __modular_multiplication((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &revocation_authority_par.randomizers[I].ecm, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);
            __multos_memcmp_fixed_length((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &rho_e1.ecm, EC_SIZE, (uint8_t *) &res);
            if (res == 0x08)
            {
                __subtraction((uint8_t *) &user_pi.s_e1, (uint8_t *) &rho_e1.ecm, (uint8_t *) &ecm_tmp1.ecm, EC_SIZE);
            }
            else
            {
                __modular_subtraction((uint8_t *) &user_pi.s_e1, (uint8_t *) &rho_e1.ecm, (uint8_t *) &ecm_tmp1.ecm, EC_SIZE, (uint8_t *) &elliptic_curve_domain.N);
            }

            // s_e2
            __multos_memzero((uint8_t *) &ecm_tmp1.ecm, SHA_DIGEST_PADDING);
            __multos_memcpy_non_atomic_fixed_length((uint8_t *) &ecm_tmp1.ecm + SHA_DIGEST_PADDING, (uint8_t *) &user_pi.e, SHA_DIGEST_LENGTH);
            __modular_multiplication((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &revocation_authority_par.randomizers[II].ecm, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);
            __multos_memcmp_fixed_length((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &rho_e2.ecm, EC_SIZE, (uint8_t *) &res);
            if (res == 0x08)
            {
                __subtraction((uint8_t *) &user_pi.s_e2, (uint8_t *) &rho_e2.ecm, (uint8_t *) &ecm_tmp1.ecm, EC_SIZE);
            }
            else
            {
                __modular_subtraction((uint8_t *) &user_pi.s_e2, (uint8_t *) &rho_e2.ecm, (uint8_t *) &ecm_tmp1.ecm, EC_SIZE, (uint8_t *) &elliptic_curve_domain.N);
            }

            // s_mr
            __multos_memzero((uint8_t *) &ecm_tmp1.ecm, SHA_DIGEST_PADDING);
            __multos_memcpy_non_atomic_fixed_length((uint8_t *) &ecm_tmp1.ecm + SHA_DIGEST_PADDING, (uint8_t *) &user_pi.e, SHA_DIGEST_LENGTH);
            __modular_multiplication((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &revocation_authority_signature.mr, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);
            __multos_memcmp_fixed_length((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &rho_mr.ecm, EC_SIZE, (uint8_t *) &res);
            if (res == 0x08)
            {
                __subtraction((uint8_t *) &user_pi.s_mr, (uint8_t *) &rho_mr.ecm, (uint8_t *) &ecm_tmp1.ecm, EC_SIZE);
            }
            else
            {
                __modular_subtraction((uint8_t *) &user_pi.s_mr, (uint8_t *) &rho_mr.ecm, (uint8_t *) &ecm_tmp1.ecm, EC_SIZE, (uint8_t *) &elliptic_curve_domain.N);
            }

            // s_mz non-disclosed attributes
            for (it = 0; it < num_non_disclosed_attributes; it++)
            {
                __multos_memzero((uint8_t *) &ecm_tmp1.ecm, SHA_DIGEST_PADDING);
                __multos_memcpy_non_atomic_fixed_length((uint8_t *) &ecm_tmp1.ecm + SHA_DIGEST_PADDING, (uint8_t *) &user_pi.e, SHA_DIGEST_LENGTH);
                __modular_multiplication((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &user_attributes.attributes[it], (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);
                __multos_memcmp_fixed_length((uint8_t *) &ecm_tmp1.ecm, (uint8_t *) &rho_mz[it].ecm, EC_SIZE, (uint8_t *) &res);
                if (res == 0x08)
                {
                    __subtraction((uint8_t *) &user_pi.s_mz[it], (uint8_t *) &rho_mz[it].ecm, (uint8_t *) &ecm_tmp1.ecm, EC_SIZE);
                }
                else
                {
                    __modular_subtraction((uint8_t *) &user_pi.s_mz[it], (uint8_t *) &rho_mz[it].ecm, (uint8_t *) &ecm_tmp1.ecm, EC_SIZE, (uint8_t *) &elliptic_curve_domain.N);
                }
            }

            offset = 0; // reset for INS_GET_PROOF_OF_KNOWLEDGE

            ExitSW(ISO7816_SW_NO_ERROR);
            break;
        }

        case INS_GET_PROOF_OF_KNOWLEDGE:
        {
            if (!CheckCase(2))
            {
                ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
                break;
            }

            if (P1 == 0x01) // send user pi
            {
                memcpy(apdu_data, (const void *) ((uint8_t *) &user_pi + offset), (size_t) Le);
                offset += (size_t) Le;

                if (Le < MAX_APDU_SEND_SIZE_T0) // last transmission of this data block
                {
                    offset = 0; // reset for next data block
                }

                SetLa(Le);
            }
            else if (P1 = 0x02) // send user credential
            {
                memcpy(apdu_data, (const void *) ((uint8_t *) &user_hash_data.user_credential + offset), (size_t) Le);
                offset += (size_t) Le;

                if (Le < MAX_APDU_SEND_SIZE_T0) // last transmission of this data block
                {
                    offset = 0; // reset for next data block
                }

                SetLa(Le);
            }

            /// TODO: fix the error with ExitSWLa!
            ExitSW(offset < sizeof(user_credential_t) ? CUSTOM_SW_EXPECTED_ADDITIONAL_DATA : ISO7816_SW_NO_ERROR);
            break;
        }

        case CMD_TEST_GET_PROOF_OF_KNOWLEDGE:
        {
            if (!CheckCase(2))
            {
                ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
                break;
            }

            /// t values
            if (P1 == 0x01)
            {
                // copy the t_verify
                memcpy(apdu_data, (const void *) &user_hash_data.user_t_values.t_verify, sizeof(elliptic_curve_point_t));
            }
            else if (P1 == 0x02)
            {
                // copy the t_revoke
                memcpy(apdu_data, (const void *) &user_hash_data.user_t_values.t_revoke, sizeof(elliptic_curve_point_t));
            }
            else if (P1 == 0x03)
            {
                // copy the t_sig
                memcpy(apdu_data, (const void *) &user_hash_data.user_t_values.t_sig, sizeof(elliptic_curve_point_t));
            }
            else if (P1 == 0x04)
            {
                // copy the t_sig1
                memcpy(apdu_data, (const void *) &user_hash_data.user_t_values.t_sig1, sizeof(elliptic_curve_point_t));
            }
            else if (P1 == 0x05)
            {
                // copy the t_sig2
                memcpy(apdu_data, (const void *) &user_hash_data.user_t_values.t_sig2, sizeof(elliptic_curve_point_t));
            }

            /// user credential
            else if (P1 == 0x06)
            {
                // copy the sigma_hat
                memcpy(apdu_data, (const void *) &user_hash_data.user_credential.sigma_hat, sizeof(elliptic_curve_point_t));
            }
            else if (P1 == 0x07)
            {
                // copy the sigma_hat_e1
                memcpy(apdu_data, (const void *) &user_hash_data.user_credential.sigma_hat_e1, sizeof(elliptic_curve_point_t));
            }
            else if (P1 == 0x08)
            {
                // copy the sigma_hat_e2
                memcpy(apdu_data, (const void *) &user_hash_data.user_credential.sigma_hat_e2, sizeof(elliptic_curve_point_t));
            }
            else if (P1 == 0x09)
            {
                // copy the sigma_minus_e1
                memcpy(apdu_data, (const void *) &user_hash_data.user_credential.sigma_minus_e1, sizeof(elliptic_curve_point_t));
            }
            else if (P1 == 0x0A)
            {
                // copy the sigma_minus_e2
                memcpy(apdu_data, (const void *) &user_hash_data.user_credential.sigma_minus_e2, sizeof(elliptic_curve_point_t));
            }
            else if (P1 == 0x0B)
            {
                // copy the pseudonym
                memcpy(apdu_data, (const void *) &user_hash_data.user_credential.pseudonym, sizeof(elliptic_curve_point_t));
            }

            ExitSWLa(ISO7816_SW_NO_ERROR, sizeof(elliptic_curve_point_t));
            break;
        }

        default:
        {
            ExitSW(ISO7816_SW_INS_NOT_SUPPORTED);
            break;
        }
    }
}

/**
 * Writes random bytes to address by cryptographically secure
 * pseudo random number generator.
 *
 * @param address pointer to where the random number will be written
 */
void set_by_csprng(unsigned char *address)
{
    __set_by_csprng(address);
    __modular_reduction(address, EC_SIZE, (uint8_t *) &elliptic_curve_domain.N, EC_SIZE);
}
