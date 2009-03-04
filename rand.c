/*
 * $Id: rand.c,v 1.2 2005/01/14 13:38:04 takashi Exp $
*/
#include "includes.h"
#include <stdlib.h>

int
loss_gen(double lossrate) /* Rand function */
{ 
    static unsigned int seq = 0;
    double   base;

//    ++seq;

    if(lossrate == 0.0){
        return 1;
    }
/*
    if (count > 0) {
        count--;
#ifdef VERBOSE
        printf("loss: seq %d\n", seq);
#endif
        return 0;
    }
    */

    base = ((double)100.0 * rand() / RAND_MAX);

    if(lossrate < base){
        return 1;
    } else {
    l_st->deny++;
#ifdef VERBOSE
        printf("loss: seq %d\n", seq);
#endif        
        return 0;
    }
}
