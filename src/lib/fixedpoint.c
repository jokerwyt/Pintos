#include "fixedpoint.h"




void printfp(fixedpoint a)
{
  printf("ipart=%d, fpart=%d/(2^14)\n", truncate(a), a & (FP_F - 1));
}