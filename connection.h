/*
    Custom Implementations of linked lists API inside Linux Kernel
*/


#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "list.h" /*This file is from Linux Kernel (include/linux/list.h) */

struct uniqueConnection {
    char* sourceIP;
    char* destinationIP;
    uint16_t sourcePort;
    uint16_t  destinationPort;
    int connectionRequests; 
    int positiveResponses;
    struct list_head list_member;
};

void add_node(char* srcIP, char* dstIP, uint16_t srcP, uint16_t destP,struct list_head *head)
{
    struct uniqueConnection *connectionNodePtr = (struct uniqueConnection *)calloc(1,sizeof(struct uniqueConnection));
    assert(connectionNodePtr != NULL);
    
    connectionNodePtr->sourceIP = malloc(strlen(srcIP)+1);  
    strcpy(connectionNodePtr->sourceIP,srcIP);

    connectionNodePtr->destinationIP = malloc(strlen(dstIP)+1);
    strcpy(connectionNodePtr->destinationIP,dstIP);

    connectionNodePtr->sourcePort = srcP;
    connectionNodePtr->destinationPort = destP;


    connectionNodePtr->connectionRequests++;

    INIT_LIST_HEAD(&connectionNodePtr->list_member);
    list_add(&connectionNodePtr->list_member, head);
}

void displayConnections(struct list_head *head)
{
    struct list_head *iter;
    struct uniqueConnection *connectionNodePtr;

    __list_for_each(iter, head) {
        connectionNodePtr = list_entry(iter, struct uniqueConnection, list_member);
        printf("sourceIP:%s \t destinationIP:%s \t connectionRequests:%d \t positiveResponses:%d \t \n", connectionNodePtr->sourceIP, connectionNodePtr->destinationIP, connectionNodePtr->connectionRequests, connectionNodePtr->positiveResponses);
    }
    printf("\n");
}

struct uniqueConnection* checkList(char* srcIP, char* dstIP,uint16_t srcP, uint16_t destP,struct list_head *head)
{
    struct list_head *iter;
    struct uniqueConnection *connectionNodePtr;

    __list_for_each(iter, head) {
        connectionNodePtr = list_entry(iter, struct uniqueConnection, list_member);
        if((strcmp(connectionNodePtr->sourceIP,srcIP)==0) && (strcmp(connectionNodePtr->destinationIP,dstIP)==0) && ((connectionNodePtr->sourcePort) == srcP) && ((connectionNodePtr->destinationPort) == destP) ) {
            return connectionNodePtr;
        }
    }

    return NULL;
}

void deleteAllConnections(struct list_head *head)
{
    struct list_head *iter;
    struct uniqueConnection *connectionNodePtr;
    
  redo:
    __list_for_each(iter, head) {
        connectionNodePtr = list_entry(iter, struct uniqueConnection, list_member);
        list_del(&connectionNodePtr->list_member);
        free(connectionNodePtr->sourceIP);
        free(connectionNodePtr->destinationIP);
        free(connectionNodePtr);
        goto redo;
    }
}