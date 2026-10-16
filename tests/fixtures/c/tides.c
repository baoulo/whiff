/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Ada Example
 * Tide calculations for the harbour.
 */
#include <stdio.h>
#include "tides.h"

#define MAX_TIDES 8

struct tide { int hour; double height; };

static double average(const struct tide *t, int n)
{
    double sum = 0; /* running total */
    for (int i = 0; i < n; i++) sum += t[i].height;
    return n ? sum / n : 0;
}

int main(void)
{
    // TODO: read tides from a file
    struct tide t[2] = {{6, 4.1}, {12, 0.9}};
    printf("%.2f\n", average(t, 2));
    return 0;
}
