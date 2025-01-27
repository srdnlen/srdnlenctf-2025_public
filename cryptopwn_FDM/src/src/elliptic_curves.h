#ifndef ELLIPTIC_CURVES_H
#define ELLIPTIC_CURVES_H

#include <gmp.h>
#include <stdbool.h>
#include <assert.h>

typedef struct {
    mpz_t p;
    mpz_t a;
    mpz_t b;
    mpz_t n;
} Curve;

typedef struct Point Point;

struct Point {
    Curve* curve;
    mpz_t x;
    mpz_t y;
    Point* O;
    bool is_O;
};

void point_set(Point* P, mpz_t x, mpz_t y, Curve* curve, Point* O);
void point_init(Point* P, mpz_t x, mpz_t y, Curve* curve, Point* O);
void point_clear(Point* P);
bool check_point(Point* P, Curve* curve);
bool point_eq(Point* A, Point* B);
Point point_negation(Point P);
void point_addition(Point* A, Point* B, Point* result);
Point scalar_multiplication(mpz_t n_, Point* P);

#endif

