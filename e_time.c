/*
 * $Date: 2004/12/29 10:21:48 $
 * $Id: e_time.c,v 1.5 2004/12/29 10:21:48 takashi Exp $
 * $Revision: 1.5 $
 */
#include "includes.h"

double e_point(struct timeval *point){
    gettimeofday(point, NULL);
}


double e_time(char *sect, struct timeval *first, struct timeval *second){
    double time = 0.0;
    int    diff;
    int t1,t2;

    t1 = second->tv_usec;
    t2 = first->tv_usec;
//    printf("%d %d \n%d %d\n",second->tv_sec, second->tv_usec, first->tv_sec, first->tv_usec);
//    printf("%d\n", second->tv_usec - first->tv_usec);
//    diff = second->tv_usec - first->tv_usec;
    diff = t1 - t2;
//    printf("%d %d %d\n",diff, t1,t2);
//    time = (double)(second->tv_usec - first->tv_usec)/1000.0;
    time = (double)(diff)/1000.0;
    printf("%s    %.3f [ms] \n", sect, time);

    return time;
}

int my_clock(){
    struct timeval tv;

    gettimeofday(&tv, NULL);
//printf("here:%d %d\n", tv.tv_sec, tv.tv_usec);
//printf("here:%d\n", (tv.tv_sec&0x0000ffff)*1000000+tv.tv_usec);
    return (tv.tv_sec&0x0000ffff)*1000000 + tv.tv_usec;
}
