/* Based on https://github.com/kokke/tiny-bignum-c.
 * Enjoy it --FXTi
 */

#include <r_util.h>

/* Functions for shifting number in-place. */
static void _lshift_one_bit (RNumBig *a);
static void _rshift_one_bit (RNumBig *a);
static void _lshift_word (RNumBig *a, int nwords);
static void _rshift_word (RNumBig *a, int nwords);
static void _r_big_zero_out(RNumBig *n);

R_API RNumBig *r_big_new() {
    RNumBig *n = R_NEW (RNumBig);
    if (n) {
        _r_big_zero_out (n);
    }
    return n;
}

R_API void r_big_free(RNumBig *b) {
    free (b);
}

R_API void r_big_from_int(RNumBig *b, DTYPE_VAR n) {
    r_return_if_fail (b);

    _r_big_zero_out (b);
    b->sign = (n < 0) ? -1 : 1;
    DTYPE_TMP v = n * b->sign;

    /* Endianness issue if machine is not little-endian? */
#ifdef WORD_SIZ
#if (WORD_SIZ == 1)
    b->array[0] = (v & 0x000000ff);
    b->array[1] = (v & 0x0000ff00) >> 8;
    b->array[2] = (v & 0x00ff0000) >> 16;
    b->array[3] = (v & 0xff000000) >> 24;
#elif (WORD_SIZ == 2)
    b->array[0] = (v & 0x0000ffff);
    b->array[1] = (v & 0xffff0000) >> 16;
#elif (WORD_SIZ == 4)
    b->array[0] = v;
    DTYPE_TMP num_32 = 32;
    DTYPE_TMP tmp = v >> num_32; 
    b->array[1] = tmp;
#endif
#endif
}

R_API DTYPE_VAR r_big_to_int(RNumBig *b) {
    r_return_val_if_fail (b, 0);

    DTYPE_TMP ret = 0;

    /* Endianness issue if machine is not little-endian? */
#if (WORD_SIZ == 1)
    ret += b->array[0];
    ret += b->array[1] << 8;
    ret += b->array[2] << 16;
    ret += b->array[3] << 24;
#elif (WORD_SIZ == 2)
    ret += b->array[0];
    ret += b->array[1] << 16;
#elif (WORD_SIZ == 4)
    ret += b->array[1];
    ret <<= 32;
    ret += b->array[0];
#endif

    if (b->sign < 0) {
        return -ret;
    } 
    return ret;
}

R_API void r_big_from_hexstr(RNumBig *n, const char *str, int nbytes) {
    r_return_if_fail (n);
    r_return_if_fail (str);

    _r_big_zero_out (n);

    if (str[0] == '-') {
        n->sign = -1;
        str += 1;
        nbytes -= 1;
    }

    if (str[0] == '0' && str[1] == 'x') {
        str += 2;
        nbytes -= 2;
    }
    r_return_if_fail (nbytes > 0);

    DTYPE tmp; 
    int i = nbytes - (2 * WORD_SIZ); /* index into string */
    int j = 0; /* index into array */

    while (i >= 0) {
        tmp = 0;
        sscanf (&str[i], SSCANF_FORMAT_STR, &tmp);
        n->array[j] = tmp;
        i -= (2 * WORD_SIZ); /* step WORD_SIZ hex-byte(s) back in the string. */
        j += 1; /* step one element forward in the array. */
    }

    if (-2 * WORD_SIZ < i && i < 0) {
        char buffer[2 * WORD_SIZ];
        memset (buffer, 0, sizeof (buffer));
        i += 2 * WORD_SIZ - 1;
        for (; i >= 0; i--) {
            buffer[i] = str[i];
        }
        tmp = 0;
        sscanf (buffer, SSCANF_FORMAT_STR, &tmp);
        n->array[j] = tmp;
    }
}

R_API char *r_big_to_hexstr(RNumBig *b, size_t *size) {
    r_return_val_if_fail (b, NULL);
    r_return_val_if_fail (size, NULL);

    int j = BN_ARRAY_SIZE - 1; /* index into array - reading "MSB" first -> big-endian */
    int i = 0; /* index into string representation. */
    int k = 0; /* Leading zero's amount */
    int z;

    for (; b->array[j] == 0 && j >= 0; --j) {}
    if (j == -1) {
        return "0x0";
    }

    *size = 3 + 2 * WORD_SIZ * (j + 1) + ((b->sign > 0) ? 0 : 1);
    char *ret_str = malloc (sizeof (char) * (*size));
    memset (ret_str, 0, sizeof (char) * (*size));

    if (b->sign < 0) {
        ret_str[i++] = '-';
    }
    ret_str[i++] = '0'; ret_str[i++] = 'x';

    sprintf(&ret_str[i], SPRINTF_FORMAT_STR, b->array[j--]);
    for (; ret_str[i + k] == '0' && k < 2*WORD_SIZ; k++) { }
    for (z = k; ret_str[i + z]; z++) {
        ret_str[i + z - k] = ret_str[i + z];
    }
    i += z - k;
    ret_str[i] = '\x00';

    for (; j >= 0; --j) {
        sprintf(&ret_str[i], SPRINTF_FORMAT_STR, b->array[j]);
        i += 2 * WORD_SIZ;
    }

    return ret_str;
}

R_API void r_big_assign(RNumBig *dst, RNumBig *src) {
    r_return_if_fail (dst);
    r_return_if_fail (src);

    memcpy (dst, src, sizeof (RNumBig));
}

static void r_big_add_inner(RNumBig *c, RNumBig *a, RNumBig *b) {
    DTYPE_TMP tmp;
    int carry = 0;
    int i;
    for (i = 0; i < BN_ARRAY_SIZE; i++) {
        tmp = (DTYPE_TMP)a->array[i] + b->array[i] + carry;
        carry = (tmp > MAX_VAL);
        c->array[i] = (tmp & MAX_VAL);
    }
}

static void r_big_sub_inner(RNumBig *c, RNumBig *a, RNumBig *b) {
    DTYPE_TMP res;
    RNumBig *tmp;
    DTYPE_TMP tmp1; 
    DTYPE_TMP tmp2;
    int borrow = 0;
    c->sign = r_big_cmp (a, b) >= 0 ? 1 : -1;
    if (c->sign < 0) {
        tmp = a;
        a = b;
        b = tmp;
    }
    int i;  
    for (i = 0; i < BN_ARRAY_SIZE; i++) {
        tmp1 = (DTYPE_TMP)a->array[i] + (MAX_VAL + 1); /* + number_base */
        tmp2 = (DTYPE_TMP)b->array[i] + borrow;

        res = (tmp1 - tmp2);
        c->array[i] = (DTYPE) (res & MAX_VAL); /* "modulo number_base" == "% (number_base - 1)" if nu    mber_base is 2^N */
        borrow = (res <= MAX_VAL);
    }
}

R_API void r_big_add(RNumBig *c, RNumBig *a, RNumBig *b) {
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (c);

    if (a->sign >= 0 && b->sign >= 0) {
        r_big_add_inner (c, a, b);
        c->sign = 1;
    }
    if (a->sign >= 0 && b->sign < 0) {
        r_big_sub_inner (c, a, b);
    }
    if (a->sign < 0 && b->sign >= 0) {
        r_big_sub_inner (c, b, a);
    }
    if (a->sign < 0 && b->sign < 0) {
        r_big_add_inner (c, a, b);
        c->sign = -1;
    }
}

R_API void r_big_sub(RNumBig *c, RNumBig *a, RNumBig *b) {
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (c);

    if (a->sign >= 0 && b->sign >= 0) {
        r_big_sub_inner (c, a, b);
    }
    if (a->sign >= 0 && b->sign < 0) {
        r_big_add_inner (c, a, b);
        c->sign = 1;
    }
    if (a->sign < 0 && b->sign >= 0) {
        r_big_add_inner (c, a, b);
        c->sign = -1;
    }
    if (a->sign < 0 && b->sign < 0) {
        r_big_sub_inner (c, b, a);
    }
}

R_API void r_big_mul(RNumBig *c, RNumBig *a, RNumBig *b) {
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (c);
    
    RNumBig *row = r_big_new();
    RNumBig *tmp = r_big_new();
    int i, j;
    
    _r_big_zero_out (c);
    
    for (i = 0; i < BN_ARRAY_SIZE; i++) {
        _r_big_zero_out (row);
        
        for (j = 0; j < BN_ARRAY_SIZE; j++) {
            if (i + j < BN_ARRAY_SIZE) {
                _r_big_zero_out (tmp);
                DTYPE_TMP intermediate = ((DTYPE_TMP)a->array[i] * (DTYPE_TMP)b->array[j]);
                r_big_from_int (tmp, intermediate);
                _lshift_word (tmp, i + j);
                r_big_add (row, row, tmp);
            }
        }
        r_big_add (c, row, c);
    }
    
    c->sign = a->sign * b->sign;
    r_big_free(row);
    r_big_free(tmp);
}

R_API void r_big_div(RNumBig *c, RNumBig *a, RNumBig *b) {
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (c);
    r_return_if_fail (r_big_is_zero (b));

    RNumBig *current = r_big_new();
    RNumBig *denom = r_big_new();;
    RNumBig *tmp = r_big_new();

    r_big_from_int (current, 1); // int current = 1;
    r_big_assign (denom, b); // denom = b
    r_big_assign (tmp, a); // tmp = a

    const DTYPE_TMP half_max = 1 + (DTYPE_TMP) (MAX_VAL / 2);
    bool overflow = false;
    while (r_big_cmp (denom, a) != 1) // while (denom <= a) {
    {
        if (denom->array[BN_ARRAY_SIZE - 1] >= half_max) {
            overflow = true;
            break;
        }
        _lshift_one_bit (current); //   current <<= 1;
        _lshift_one_bit (denom); //   denom <<= 1;
    }
    if (!overflow) {
        _rshift_one_bit (denom); // denom >>= 1;
        _rshift_one_bit (current); // current >>= 1;
    }
    _r_big_zero_out (c); // int answer = 0;

    while (!r_big_is_zero (current)) // while (current != 0)
    {
        if (r_big_cmp (tmp, denom) != -1) //   if (dividend >= denom)
        {
            r_big_sub (tmp, tmp, denom); //     dividend -= denom;
            r_big_or (c, current, c); //     answer |= current;
        }
        _rshift_one_bit (current); //   current >>= 1;
        _rshift_one_bit (denom); //   denom >>= 1;
    } // return answer;

    c->sign = a->sign * b->sign;
    r_big_free (current);
    r_big_free (denom);
    r_big_free (tmp);
}

R_API void r_big_mod(RNumBig *c, RNumBig *a, RNumBig *b) {
    /*  
    Take divmod and throw away div part
    */
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (c);
    r_return_if_fail (r_big_is_zero (b));
    
    RNumBig *tmp = r_big_new();
    
    r_big_divmod (tmp, c, a, b);

    r_big_free (tmp);
}

R_API void r_big_divmod(RNumBig *c, RNumBig *d, RNumBig *a, RNumBig *b) {
    /*
    Puts a%b in d 
    and a/b in c
        
    mod(a,b) = a - ((a / b) * b)
    
    example:
      mod(8, 3) = 8 - ((8 / 3) * 3) = 2
    */    
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (c);
    r_return_if_fail (r_big_is_zero (b));
    
    RNumBig *tmp = r_big_new();
        
    /* c = (a / b) */                                                                                
    r_big_div (c, a, b);

    /* tmp = (c * b) */
    r_big_mul (tmp, c, b);
    
    /* d = a - tmp */
    r_big_sub (d, a, tmp);

    r_big_free (tmp);
}

R_API void r_big_and(RNumBig *c, RNumBig *a, RNumBig *b) {
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (c);
    r_return_if_fail (a->sign > 0);
    r_return_if_fail (b->sign > 0);

    int i;
    for (i = 0; i < BN_ARRAY_SIZE; i++) {
        c->array[i] = (a->array[i] & b->array[i]);
    }
}

R_API void r_big_or(RNumBig *c, RNumBig *a, RNumBig *b) {
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (c);
    r_return_if_fail (a->sign > 0);
    r_return_if_fail (b->sign > 0);

    int i;
    for (i = 0; i < BN_ARRAY_SIZE; i++) {
        c->array[i] = (a->array[i] | b->array[i]);
    }
}

R_API void r_big_xor(RNumBig *c, RNumBig *a, RNumBig *b) {
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (c);
    r_return_if_fail (a->sign > 0);
    r_return_if_fail (b->sign > 0);

    int i;
    for (i = 0; i < BN_ARRAY_SIZE; i++) {
        c->array[i] = (a->array[i] ^ b->array[i]);
    }
}

R_API void r_big_lshift(RNumBig *b, RNumBig *a, size_t nbits) {
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (nbits >= 0);
    r_return_if_fail (a->sign > 0);
    r_return_if_fail (b->sign > 0);

    r_big_assign (b, a);
    /* Handle shift in multiples of word-size */
    const int nbits_pr_word = (WORD_SIZ * 8);
    int nwords = nbits / nbits_pr_word;
    if (nwords != 0) {
        _lshift_word (b, nwords);
        nbits -= (nwords * nbits_pr_word);
    }

    if (nbits != 0) {
        int i;
        for (i = (BN_ARRAY_SIZE - 1); i > 0; i--) {
            b->array[i] = (b->array[i] << nbits) | (b->array[i - 1] >> ((8 * WORD_SIZ) - nbits));
        }
        b->array[i] <<= nbits;
    }
}
        
R_API void r_big_rshift(RNumBig *b, RNumBig *a, size_t nbits) {
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (nbits >= 0);
    r_return_if_fail (a->sign > 0);
    r_return_if_fail (b->sign > 0);

    r_big_assign (b, a);
    /* Handle shift in multiples of word-size */                                                     
    const int nbits_pr_word = (WORD_SIZ * 8);
    int nwords = nbits / nbits_pr_word;
    if (nwords != 0) {
        _rshift_word (b, nwords);
        nbits -= (nwords * nbits_pr_word);
    }
    
    if (nbits != 0) {
        int i; 
        for (i = 0; i < (BN_ARRAY_SIZE - 1); i++) {
            b->array[i] = (b->array[i] >> nbits) | (b->array[i + 1] << ((8 * WORD_SIZ) - nbits));
        }
        b->array[i] >>= nbits;
    }
}

R_API int r_big_cmp(RNumBig *a, RNumBig *b) {
    r_return_val_if_fail (a, 0);
    r_return_val_if_fail (b, 0);

    if (a->sign != b->sign)
        return a->sign > 0 ? 1 : -1;

    int i = BN_ARRAY_SIZE;
    do {
        i -= 1; /* Decrement first, to start with last array element */
        if (a->array[i] > b->array[i]) {
            return 1 * a->sign;
        }
        if (a->array[i] < b->array[i]) {
            return -1 * a->sign;
        }
    } while (i != 0);
        
    return 0;
}
    
R_API int r_big_is_zero(RNumBig *a) {
    r_return_val_if_fail (a, -1);
    
    int i;
    for (i = 0; i < BN_ARRAY_SIZE; i++) {
        if (a->array[i]) {
            return 0;
        }
    }

    return 1;
}

R_API void r_big_inc(RNumBig *a) {
    r_return_if_fail (a);
    RNumBig *tmp = r_big_new();

    r_big_from_int (tmp, 1);
    r_big_add (a, a, tmp);

    r_big_free (tmp);
}

R_API void r_big_dec(RNumBig *a) {
    r_return_if_fail (a);
    RNumBig *tmp = r_big_new();

    r_big_from_int (tmp, 1);
    r_big_sub (a, a, tmp);

    r_big_free (tmp);
}

R_API void r_big_pow(RNumBig *c, RNumBig *a, RNumBig *b) {
    r_return_if_fail (a);
    r_return_if_fail (b);
    r_return_if_fail (c);
    //  FIXME: Use quick pow

    RNumBig *tmp = r_big_new();

    _r_big_zero_out (c);

    if (r_big_cmp (b, c) == 0) {
        /* Return 1 when exponent is 0 -- n^0 = 1 */
        r_big_inc (c);
    } else {
        RNumBig *bcopy = r_big_new();
        r_big_assign (bcopy, b);

        /* Copy a -> tmp */
        r_big_assign (tmp, a);

        r_big_dec (bcopy);

        /* Begin summing products: */
        while (!r_big_is_zero (bcopy)) {

            /* c = tmp * tmp */
            r_big_mul (c, a, tmp);
            /* Decrement b by one */
            r_big_dec (bcopy);

            r_big_assign (tmp, c);
        }

        /* c = tmp */
        r_big_assign (c, tmp);
        r_big_free (bcopy);
    }
    
    r_big_free (tmp);
}

R_API void r_big_isqrt(RNumBig *b, RNumBig *a) {
    r_return_if_fail (a);
    r_return_if_fail (b);

    RNumBig *tmp = r_big_new();
    RNumBig *low = r_big_new();
    RNumBig *high = r_big_new();
    RNumBig *mid = r_big_new();

    r_big_assign (high, a);
    r_big_rshift (mid, high, 1);
    r_big_inc (mid);

    while (r_big_cmp (high, low) > 0) {
        r_big_mul (tmp, mid, mid);
        if (r_big_cmp (tmp, a) > 0) {
            r_big_assign (high, mid);
            r_big_dec (high);
        } else {
            r_big_assign (low, mid);
        }
        r_big_sub (mid, high, low);
        _rshift_one_bit (mid);
        r_big_add (mid, mid, low);
        r_big_inc (mid);
    }
    r_big_assign (b, low);

    r_big_free (tmp);
    r_big_free (low);
    r_big_free (high);
    r_big_free (mid);
}

/* Private / Static functions. */
static void _rshift_word (RNumBig *a, int nwords) {
    /* Naive method: */
    r_return_if_fail (a);
    r_return_if_fail (nwords >= 0);
    
    size_t i;
    if (nwords >= BN_ARRAY_SIZE) {
        for (i = 0; i < BN_ARRAY_SIZE; i++) {
            a->array[i] = 0;
        }
        return;
    }
    
    for (i = 0; i < BN_ARRAY_SIZE - nwords; i++) {
        a->array[i] = a->array[i + nwords]; 
    }   
    for (; i < BN_ARRAY_SIZE; i++) {
        a->array[i] = 0;
    }
}   

static void _lshift_word (RNumBig *a, int nwords) {
    r_return_if_fail (a);
    r_return_if_fail (nwords >= 0);
    
    int i;
    /* Shift whole words */
    for (i = (BN_ARRAY_SIZE - 1); i >= nwords; i--) {
        a->array[i] = a->array[i - nwords];
    }
    /* Zero pad shifted words. */
    for (; i >= 0; i--) {
        a->array[i] = 0;
    }   
}       
    
static void _lshift_one_bit (RNumBig *a) {
    r_return_if_fail (a);
    
    int i;
    for (i = (BN_ARRAY_SIZE - 1); i > 0; i--) {
        a->array[i] = (a->array[i] << 1) | (a->array[i - 1] >> ((8 * WORD_SIZ) - 1));
    }   
    a->array[0] <<= 1;
}   
        
static void _rshift_one_bit (RNumBig *a) {
    r_return_if_fail (a);
    
    int i; 
    for (i = 0; i < (BN_ARRAY_SIZE - 1); i++) {
        a->array[i] = (a->array[i] >> 1) | (a->array[i + 1] << ((8 * WORD_SIZ) - 1));
    }
    a->array[BN_ARRAY_SIZE - 1] >>= 1;
}

static void _r_big_zero_out(RNumBig *a) {
    r_return_if_fail (a);

    size_t i;
    for (i = 0; i < BN_ARRAY_SIZE; i++) {
        a->array[i] = 0;
    }
    a->sign = 1; /* hack to avoid -0 */
}
