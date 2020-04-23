/*
 *  Dcrm SDK
 *
 *  Copyright (C) 2018-2019  Fusion Foundation Ltd. All rights reserved.
 *  Copyright (C) 2018-2019 caihaijun@fusion.org
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#ifndef _SECP256K1_DCRM_EXT_
# define _SECP256K1_DCRM_EXT_

int dcrm_secp256k1_get_ecdsa_sign_v(const secp256k1_context* ctx, unsigned char *point,const unsigned char *scalar)
{
	int ret = 0;
	int overflow = 0;
	secp256k1_fe feY;
	secp256k1_scalar s;

	secp256k1_fe_set_b32(&feY, point);
	secp256k1_scalar_set_b32(&s, scalar, &overflow);
	
	ret = (overflow ? 2 : 0) | (secp256k1_fe_is_odd(&feY) ? 1 : 0);
	return ret;
}

#endif
