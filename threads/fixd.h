#define FRACTION (1 << 14)  
#define INT_TO_FP(n) ((n) * FRACTION)
#define FP_TO_INT_ZERO(x) ((x) / FRACTION)
#define FP_TO_INT_NEAREST(x) (((x) >= 0) ? (((x) + FRACTION / 2) / FRACTION) : (((x) - FRACTION / 2) / FRACTION))
#define FP_ADD_FP(x, y) ((x) + (y))
#define FP_SUB_FP(x, y) ((x) - (y))
#define FP_ADD_INT(x, n) ((x) + (n) * FRACTION)
#define FP_SUB_INT(x, n) ((x) - (n) * FRACTION)
#define FP_MULT_INT(x, n) ((x) * (n))
#define FP_MULT_FP(x, y) ((((int64_t) x) * (y)) / FRACTION)
#define FP_DIV_INT(x, n) ((x) / (n))
#define FP_DIV_FP(x, y) ((((int64_t) x) * FRACTION) / (y))