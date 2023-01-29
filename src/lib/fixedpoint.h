/** 17-14 fixed point */

#ifndef __LIB_FIXEDPOINT_H
#define __LIB_FIXEDPOINT_H


#include <stdint.h>
#include <stdio.h>

typedef int32_t fixedpoint;
#define FP_FRAC (14)
#define FP_F (1 << FP_FRAC)

#define makefp(ipart, fpart) ((fixedpoint) (ipart * FP_F + fpart))
#define intfp(a) ((a) << FP_FRAC)
#define truncate(a) ((a) >> FP_FRAC)
#define roundfp(a) (((a) >= 0 ? ((a) + FP_F / 2)  : ((a) - FP_F / 2)) >> FP_FRAC)
#define mult(a, b) ((int64_t) (a) * (b) >> FP_FRAC)
#define div(a, b) ((((int64_t) (a) << FP_FRAC) / (b)))
#define mult_n(a, b) ((a) * (b))
#define div_n(a, b) ((a) / (b))
#define sub_n(a, b) ((a) - ((b) << FP_FRAC))
#define add_n(a, b) ((a) + ((b) << FP_FRAC))


void printfp(fixedpoint a);

#endif
