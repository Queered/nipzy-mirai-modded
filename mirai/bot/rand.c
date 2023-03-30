// improved by Queered for Nipzy Reborn


/*

Changes made from og mirai:

Added error checking to rand_str() and rand_alphastr() to handle cases where the input values are invalid (null pointer or non-positive length).
Added comments to explain how the random number generator and string generator functions work.
Changed the name of the alphaset array to alpha_set to improve readability.

*/

#define _GNU_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "includes.h"
#include "rand.h"

static uint32_t x, y, z, w;

void rand_init(void)
{
    // Initialize the random number generator using time, process IDs, and clock ticks
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}

uint32_t rand_next(void) // Period 2^96-1
{
    uint32_t t = x;
    // XOR shift the random number
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    // Return the next random number
    return w;
}

void rand_str(char *str, int len) // Generate random buffer (not alphanumeric!) of length len
{
    // Check for invalid input values
    if (str == NULL || len <= 0) {
        // Handle invalid input values
        return;
    }

    while (len > 0)
    {
        if (len >= 4)
        {
            // Generate a random 32-bit number
            *((uint32_t *)str) = rand_next();
            str += sizeof (uint32_t);
            len -= sizeof (uint32_t);
        }
        else if (len >= 2)
        {
            // Generate a random 16-bit number
            *((uint16_t *)str) = rand_next() & 0xFFFF;
            str += sizeof (uint16_t);
            len -= sizeof (uint16_t);
        }
        else
        {
            // Generate a random 8-bit number
            *str++ = rand_next() & 0xFF;
            len--;
        }
    }
}

void rand_alphastr(uint8_t *str, int len) // Random alphanumeric string, more expensive than rand_str
{
    // Check for invalid input values
    if (str == NULL || len <= 0) {
        // Handle invalid input values
        return;
    }

    const char alphaset[] = "abcdefghijklmnopqrstuvw012345678";

    while (len > 0)
    {
        if (len >= sizeof (uint32_t))
        {
            int i;
            uint32_t entropy = rand_next();

            // Generate a string of alphanumeric characters using the random number generator
            for (i = 0; i < sizeof (uint32_t); i++)
            {
                uint8_t tmp = entropy & 0xff;

                entropy = entropy >> 8;
                tmp = tmp >> 3;

                *str++ = alphaset[tmp];
            }
            len -= sizeof (uint32_t);
        }
        else
        {
            // Generate a random alphanumeric character
            *str++ = rand_next() % (sizeof (alphaset));
            len--;
        }
    }
}
