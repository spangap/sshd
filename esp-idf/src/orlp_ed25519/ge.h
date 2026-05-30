#ifndef GE_H
#define GE_H

#include "fe.h"


/*
ge means group element.

Here the group is the set of pairs (x,y) of field elements (see fe.h)
satisfying -x^2 + y^2 = 1 + d x^2y^2
where d = -121665/121666.

Representations:
  orlp_ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
  orlp_ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
  orlp_ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
  orlp_ge_precomp (Duif): (y+x,y-x,2dxy)
*/

typedef struct {
  fe X;
  fe Y;
  fe Z;
} orlp_ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} orlp_ge_p3;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} orlp_ge_p1p1;

typedef struct {
  fe yplusx;
  fe yminusx;
  fe xy2d;
} orlp_ge_precomp;

typedef struct {
  fe YplusX;
  fe YminusX;
  fe Z;
  fe T2d;
} orlp_ge_cached;

void orlp_ge_p3_tobytes(unsigned char *s, const orlp_ge_p3 *h);
void orlp_ge_tobytes(unsigned char *s, const orlp_ge_p2 *h);
int orlp_ge_frombytes_negate_vartime(orlp_ge_p3 *h, const unsigned char *s);

void orlp_ge_add(orlp_ge_p1p1 *r, const orlp_ge_p3 *p, const orlp_ge_cached *q);
void orlp_ge_sub(orlp_ge_p1p1 *r, const orlp_ge_p3 *p, const orlp_ge_cached *q);
void orlp_ge_double_scalarmult_vartime(orlp_ge_p2 *r, const unsigned char *a, const orlp_ge_p3 *A, const unsigned char *b);
void orlp_ge_madd(orlp_ge_p1p1 *r, const orlp_ge_p3 *p, const orlp_ge_precomp *q);
void orlp_ge_msub(orlp_ge_p1p1 *r, const orlp_ge_p3 *p, const orlp_ge_precomp *q);
void orlp_ge_scalarmult_base(orlp_ge_p3 *h, const unsigned char *a);

void orlp_ge_p1p1_to_p2(orlp_ge_p2 *r, const orlp_ge_p1p1 *p);
void orlp_ge_p1p1_to_p3(orlp_ge_p3 *r, const orlp_ge_p1p1 *p);
void orlp_ge_p2_0(orlp_ge_p2 *h);
void orlp_ge_p2_dbl(orlp_ge_p1p1 *r, const orlp_ge_p2 *p);
void orlp_ge_p3_0(orlp_ge_p3 *h);
void orlp_ge_p3_dbl(orlp_ge_p1p1 *r, const orlp_ge_p3 *p);
void orlp_ge_p3_to_cached(orlp_ge_cached *r, const orlp_ge_p3 *p);
void orlp_ge_p3_to_p2(orlp_ge_p2 *r, const orlp_ge_p3 *p);

#endif
