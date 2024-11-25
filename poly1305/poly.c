#include <stdlib.h>
#include <string.h>
#include <stdio.h>


/* pick 32-bit unsigned integer in little endian order */
unsigned int U8TOU32(const unsigned char *p)
{
    return (((unsigned int)(p[0] & 0xff)) |
            ((unsigned int)(p[1] & 0xff) << 8) |
            ((unsigned int)(p[2] & 0xff) << 16) |
            ((unsigned int)(p[3] & 0xff) << 24));
}



typedef unsigned int u32;
typedef unsigned long long u64;

#define CONSTANT_TIME_CARRY(a,b) ( \
         (a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1) \
         )
#define POLY1305_BLOCK_SIZE  16

typedef struct {
    u32 h[5];
    u32 r[4];
} poly1305_internal;

void U32TO8(unsigned char *p, unsigned int v)
{
    p[0] = (unsigned char)((v) & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

void poly1305_init(void *ctx, const unsigned char key[16])
{
    poly1305_internal *st = (poly1305_internal *) ctx;

    /* h = 0 */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    st->r[0] = U8TOU32(&key[0]) & 0x0fffffff;
    //printf("%llx\n", st->r[0]);
    st->r[1] = U8TOU32(&key[4]) & 0x0ffffffc;
    //printf("%llx\n", st->r[1]);
    st->r[2] = U8TOU32(&key[8]) & 0x0ffffffc;
    //printf("%llx\n", st->r[2]);
    st->r[3] = U8TOU32(&key[12]) & 0x0ffffffc;
    //printf("%llx\n", st->r[3]);
}

void poly1305_blocks(void *ctx, const unsigned char *inp, size_t len, u32 padbit)
{
    poly1305_internal *st = (poly1305_internal *)ctx;
    u32 r0, r1, r2, r3;
    u32 s1, s2, s3;
    u32 h0, h1, h2, h3, h4, c;
    u64 d0, d1, d2, d3;

    r0 = st->r[0];
    r1 = st->r[1];
    r2 = st->r[2];
    r3 = st->r[3];

    s1 = r1 + (r1 >> 2);
    s2 = r2 + (r2 >> 2);
    s3 = r3 + (r3 >> 2);

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    while (len >= POLY1305_BLOCK_SIZE) {
        /* h += m[i] */
        h0 = (u32)(d0 = (u64)h0 + U8TOU32(inp + 0));
        h1 = (u32)(d1 = (u64)h1 + (d0 >> 32) + U8TOU32(inp + 4));
        h2 = (u32)(d2 = (u64)h2 + (d1 >> 32) + U8TOU32(inp + 8));
        h3 = (u32)(d3 = (u64)h3 + (d2 >> 32) + U8TOU32(inp + 12));
        h4 += (u32)(d3 >> 32) + padbit;

        // /* h *= r "%" p, where "%" stands for "partial remainder" */
        d0 = ((u64)h0 * r0) +
             ((u64)h1 * s3) +
             ((u64)h2 * s2) +
             ((u64)h3 * s1);
        d1 = ((u64)h0 * r1) +
             ((u64)h1 * r0) +
             ((u64)h2 * s3) +
             ((u64)h3 * s2) +
             (h4 * s1);
        d2 = ((u64)h0 * r2) +
             ((u64)h1 * r1) +
             ((u64)h2 * r0) +
             ((u64)h3 * s3) +
             (h4 * s2);
        d3 = ((u64)h0 * r3) +
             ((u64)h1 * r2) +
             ((u64)h2 * r1) +
             ((u64)h3 * r0) +
             (h4 * s3);
        h4 = (h4 * r0);

        /* last reduction step: */
        /* a) h4:h0 = h4<<128 + d3<<96 + d2<<64 + d1<<32 + d0 */
        h0 = (u32)d0;
        h1 = (u32)(d1 += d0 >> 32);
        h2 = (u32)(d2 += d1 >> 32);
        h3 = (u32)(d3 += d2 >> 32);
        h4 += (u32)(d3 >> 32);
        /* b) (h4:h0 += (h4:h0>>130) * 5) %= 2^130 */
        c = (h4 >> 2) + (h4 & ~3U);
        h4 &= 3;
        h0 += c;
        h1 += (c = CONSTANT_TIME_CARRY(h0,c));
        h2 += (c = CONSTANT_TIME_CARRY(h1,c));
        h3 += (c = CONSTANT_TIME_CARRY(h2,c));
        h4 += CONSTANT_TIME_CARRY(h3,c);
        /*
         * Occasional overflows to 3rd bit of h4 are taken care of
         * "naturally". If after this point we end up at the top of
         * this loop, then the overflow bit will be accounted for
         * in next iteration. If we end up in poly1305_emit, then
         * comparison to modulus below will still count as "carry
         * into 131st bit", so that properly reduced value will be
         * picked in conditional move.
         */

        inp += POLY1305_BLOCK_SIZE;
        len -= POLY1305_BLOCK_SIZE;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

void poly1305_emit(void *ctx, unsigned char mac[16],
                          const u32 nonce[4])
{
    poly1305_internal *st = (poly1305_internal *) ctx;
    u32 h0, h1, h2, h3, h4;
    u32 g0, g1, g2, g3, g4;
    u64 t;
    u32 mask;

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    /* compare to modulus by computing h + -p */
    g0 = (u32)(t = (u64)h0 + 5);
    g1 = (u32)(t = (u64)h1 + (t >> 32));
    g2 = (u32)(t = (u64)h2 + (t >> 32));
    g3 = (u32)(t = (u64)h3 + (t >> 32));
    g4 = h4 + (u32)(t >> 32);

    /* if there was carry into 131st bit, h3:h0 = g3:g0 */
    mask = 0 - (g4 >> 2);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;

    /* mac = (h + nonce) % (2^128) */
    h0 = (u32)(t = (u64)h0 + nonce[0]);
    h1 = (u32)(t = (u64)h1 + (t >> 32) + nonce[1]);
    h2 = (u32)(t = (u64)h2 + (t >> 32) + nonce[2]);
    h3 = (u32)(t = (u64)h3 + (t >> 32) + nonce[3]);

    U32TO8(mac + 0, h0);
    U32TO8(mac + 4, h1);
    U32TO8(mac + 8, h2);
    U32TO8(mac + 12, h3);
}

int main()
{
    char testInput[16] = {0, 0, 0, 0, 0, 0, 0, 0, 252, 255, 255, 15, 252, 255, 255, 15};
    long long opaque[24] = {0,5,5,0,18446744069414584320,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    poly1305_init(&opaque, testInput);
    
    for(int i = 0; i < 24; i++){
        // unsigned char bytes[sizeof(double)];
        // // 将 double 类型的值复制到字节数组中
        // memcpy(bytes, &opaque[i], sizeof(double));
        // for (int i = sizeof(double) - 1; i >= 0; i--) {
        //     printf("%02x", bytes[i]);
        // }
        // printf("\n");
        printf("%llx\n", opaque[i]);
    }
}