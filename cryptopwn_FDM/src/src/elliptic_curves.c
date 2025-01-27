#include "elliptic_curves.h"

void point_set(Point* P, mpz_t x, mpz_t y, Curve* curve, Point* O) {
    mpz_set(P->x, x);
    mpz_set(P->y, y);
    P->curve = curve;
    if (mpz_cmp_ui(P->x, 0) != 0 || mpz_cmp_ui(P->y, 0) != 0) {
        P->O = O;
        P->is_O = false;
    }
    else {
        P->O = NULL;
        P->is_O = true;
    }
}

void point_init(Point* P, mpz_t x, mpz_t y, Curve* curve, Point* O) {
    mpz_init(P->x);
    mpz_init(P->y);
	point_set(P, x, y, curve, O);
}

void point_clear(Point* P) {
    mpz_clear(P->x);
    mpz_clear(P->y);
}

bool check_point(Point* P, Curve* curve) {
    if (P->is_O) {
        return false;
    }

    mpz_t square_y;
    mpz_init(square_y);
    mpz_mul(square_y, P->y, P->y);
    mpz_mod(square_y, square_y, curve->p);

    mpz_t calc_square_y;
    mpz_init_set(calc_square_y, P->x);
    mpz_mul(calc_square_y, calc_square_y, calc_square_y);
    mpz_add(calc_square_y, calc_square_y, curve->a);
    mpz_mul(calc_square_y, calc_square_y, P->x);
    mpz_add(calc_square_y, calc_square_y, curve->b);
    mpz_mod(calc_square_y, calc_square_y, curve->p);

    bool res = mpz_cmp(square_y, calc_square_y) == 0;

    mpz_clear(square_y);
    mpz_clear(calc_square_y);

    if (res) {
        Point tmp = scalar_multiplication(curve->n, P);
        res &= tmp.is_O;
    }

    return res;
}

bool point_eq(Point* A, Point* B) {
    return mpz_cmp(A->x, B->x) == 0 && mpz_cmp(A->y, B->y) == 0;
}

Point point_negation(Point P) {
    Point R;
    R.curve = P.curve;
    R.O = P.O;
    R.is_O = P.is_O;
    mpz_neg(P.y, P.y);
    mpz_init_set(R.x, P.x);
    mpz_init_set(R.y, P.y);

    mpz_clear(P.x);
    mpz_clear(P.y);

    return R;
}

void point_addition(Point* A, Point* B, Point* result) {
    assert(A->curve == B->curve);

    if (A->is_O) {
		point_set(result, B->x, B->y, B->curve, B->O);
        return;
    }
    if (B->is_O) {
		point_set(result, A->x, A->y, A->curve, A->O);
        return;
    }

    mpz_t x1, y1, x2, y2;
    mpz_init_set(x1, A->x);
    mpz_init_set(y1, A->y);
    mpz_init_set(x2, B->x);
    mpz_init_set(y2, B->y);

    mpz_t neg_y2;
    mpz_init(neg_y2);
    mpz_neg(neg_y2, y2);
    mpz_mod(neg_y2, neg_y2, A->curve->p);

    if (mpz_cmp(x1, x2) == 0 && mpz_cmp(y1, neg_y2) == 0) {
        mpz_clear(x1);
        mpz_clear(y1);
        mpz_clear(x2);
        mpz_clear(y2);
		mpz_clear(neg_y2);
		point_set(result, A->O->x, A->O->y, A->curve, NULL);
		return;
    }
    else {
        mpz_clear(neg_y2);
    }

    mpz_t lambda, tmp;
    mpz_init_set_ui(lambda, 1);
    mpz_init(tmp);
    if (!point_eq(A, B)) {
        mpz_sub(lambda, y2, y1);
        mpz_sub(tmp, x2, x1);
        mpz_invert(tmp, tmp, A->curve->p);
        mpz_mul(lambda, lambda, tmp);
        mpz_mod(lambda, lambda, A->curve->p);
    }
    else {
        mpz_set(lambda, x1);
        mpz_mul(lambda, lambda, lambda);
        mpz_mul_ui(lambda, lambda, 3);
        mpz_add(lambda, lambda, A->curve->a);
        mpz_set(tmp, y1);
        mpz_mul_ui(tmp, tmp, 2);
        mpz_invert(tmp, tmp, A->curve->p);
        mpz_mul(lambda, lambda, tmp);
        mpz_mod(lambda, lambda, A->curve->p);
    }

    mpz_clear(tmp);

    mpz_t x3, y3;

    mpz_init_set(x3, lambda);
    mpz_mul(x3, x3, lambda);
    mpz_sub(x3, x3, x1);
    mpz_sub(x3, x3, x2);
    mpz_mod(x3, x3, A->curve->p);

    mpz_init_set(y3, x1);
    mpz_sub(y3, y3, x3);
    mpz_mul(y3, y3, lambda);
    mpz_sub(y3, y3, y1);
    mpz_mod(y3, y3, A->curve->p);

    point_set(result, x3, y3, A->curve, A->O);

    mpz_clear(x1);
    mpz_clear(y1);
    mpz_clear(x2);
    mpz_clear(y2);
    mpz_clear(x3);
    mpz_clear(y3);
    mpz_clear(lambda);
}

Point scalar_multiplication(mpz_t n_, Point* P_) {
    mpz_t n;
    mpz_init_set(n, n_);

    mpz_t Px, Py;
    mpz_init_set(Px, P_->x);
    mpz_init_set(Py, P_->y);
    Point P;
    point_init(&P, Px, Py, P_->curve, P_->O);
    mpz_clear(Px);
    mpz_clear(Py);

    Point R = *P.O;
    R.curve = P.curve;

    while (mpz_cmp_ui(n, 0) > 0) {
        if (mpz_even_p(n) == 0) {
            point_addition(&R, &P, &R);
        }
        point_addition(&P, &P, &P);
        mpz_div_ui(n, n, 2);
    }

    mpz_clear(n);
    mpz_clear(P.x);
    mpz_clear(P.y);

    return R;
}
