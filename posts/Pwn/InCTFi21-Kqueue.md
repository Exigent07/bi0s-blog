---
title: Kqueue - InCTF Internationals 2021
date: 2021-08-17 12:00:00
author: Cyb0rG
author_url: https://twitter.com/_Cyb0rG
categories:
  - Pwn
tags:
  - Exploitation
  - Linux Kernel
  - Kernel Heap
  - InCTFi
---

**tl;dr**

+ Use the integer overflow to trigger a kernel heap overflow.
+ Use the heap overflow to overwrite `tty` structure function pointers to get code execution.

<!--more-->

**Challenge Points:** 986
**No of Solves:** 7
**Challenge Author:** [Cyb0rG](https://twitter.com/_Cyb0rG)

## Challenge description

`A long queue awaits you in ring0`

To start with , the challenge handout folder comes with `bzImage`, `rootfs.cpio`, `run.sh` and source code files.

We immediately see that `smep` and `smap` are disabled in the `run.sh`.

## Analysis

The module implements `create`, `delete` , `edit` and `save` functionalities.

Before heading to the functionalities, it is better we refer to the important structures being used for various operations.

### Queue structure

```c
typedef struct{
    uint16_t data_size;
    uint64_t queue_size; /* This needs to handle larger numbers */
    uint32_t max_entries;
    uint16_t idx;
    char* data;
}queue;
```

### Structure of each entry in queue
```c
struct queue_entry{
    uint16_t idx;
    char *data;
    queue_entry *next;
};
```

### Structure of request from userspace

```c
typedef struct{
    uint32_t max_entries;
    uint16_t data_size;
    uint16_t entry_idx;
    uint16_t queue_idx;
    char* data;
}request_t;
```

1. **Create_kqueue** - 

```c
static noinline long create_kqueue(request_t request){
    long result = INVALID;

    if(queueCount > MAX_QUEUES)
        err("[-] Max queue count reached");

    /* You can't ask for 0 queues , how meaningless */
    if(request.max_entries<1)
        err("[-] kqueue entries should be greater than 0");

    /* Asking for too much is also not good */
    if(request.data_size>MAX_DATA_SIZE)
        err("[-] kqueue data size exceed");

    /* Initialize kqueue_entry structure */
    queue_entry *kqueue_entry;
```
Here are the observations we can make from the necessary checks happening above -
+ `queueCount` must not exceed 5.
+ `request.max_entries` should not be less than 1.
+ `request.data_size` should not exceed 0x20.
+ `request.data_size` is the size of each queue entry and within a queue , each entry has the same `data_size`.

```c
    /* Check if multiplication of 2 64 bit integers results in overflow */
    ull space = 0;
    if(__builtin_umulll_overflow(sizeof(queue_entry),(request.max_entries+1),&space) == true)
        err("[-] Integer overflow");

    /* Size is the size of queue structure + size of entry * request entries */
    ull queue_size = 0;
    if(__builtin_saddll_overflow(sizeof(queue),space,&queue_size) == true)
        err("[-] Integer overflow");

    /* Total size should not exceed a certain limit */
    if(queue_size>sizeof(queue) + 0x10000)
        err("[-] Max kqueue alloc limit reached");
```

+ Here we see that multiplication of `sizeof(queue_entry)` and `request.max_entries+1` is being stored in `space` after making sure that it doesn't overflow 64 bits.
+ We see the addition of `sizeof(queue)` and the above result of multiplication being stored in `queue_size`.

So each queue is essentially creating space for it's entries , the number of entries come from the `request.max_entries` which determine the size of the entire queue.

```c
    /* All checks done , now call kmalloc */
    queue *queue = validate((char *)kmalloc(queue_size,GFP_KERNEL));

    /* Main queue can also store data */
    queue->data = validate((char *)kmalloc(request.data_size,GFP_KERNEL));

    /* Fill the remaining queue structure */
    queue->data_size   = request.data_size;
    queue->max_entries = request.max_entries;
    queue->queue_size  = queue_size;
```

Once above checks are done, the queue is allocated. Also since the [main queue](#queue-structure) has a data field, it's data is allocated on heap.

After that, the queue structure fields are populated.

Every entry of queue also needs to be allocated memory for storing data , and this happens next.

```c
    /* Get to the place from where memory has to be handled */
    kqueue_entry = (queue_entry *)((uint64_t)(queue + (sizeof(queue)+1)/8));

    /* Allocate all kqueue entries */
    queue_entry* current_entry = kqueue_entry;
    queue_entry* prev_entry = current_entry;

    uint32_t i=1;
    for(i=1;i<request.max_entries+1;i++){
        if(i!=request.max_entries)
            prev_entry->next = NULL;
        current_entry->idx = i;
        current_entry->data = (char *)(validate((char *)kmalloc(request.data_size,GFP_KERNEL)));

        /* Increment current_entry by size of queue_entry */
        current_entry += sizeof(queue_entry)/16;

        /* Populate next pointer of the previous entry */
        prev_entry->next = current_entry;
        prev_entry = prev_entry->next;
    }
```

In the above code , we see how we now reach the memory location from where remaining entries of the queue need to be allocated.

+ We iterate `max_entries` number of times, populate the `idx` field of the [kqueue_entry](#structure-of-each-entry-in-queue), the data field and finally populate the `next` pointer if more than 1 entries exist.

```c
    /* Find an appropriate slot in kqueues */
    uint32_t j = 0;
    for(j=0;j<MAX_QUEUES;j++){
        if(kqueues[j] == NULL)
            break;
    }

    if(j>MAX_QUEUES)
        err("[-] No kqueue slot left");

    /* Assign the newly created kqueue to the kqueues */
    kqueues[j] = queue;
    queueCount++;
    result = 0;
    return result;
}
```

+ Finally , after allocating memory for all queue entries, we now store the queue on a global array and increment the `queueCount`.

Before going forward, let's have a visual look of memory when a queue gets allocated.

```sh
0xffff88801edfc3f8:     0x0000000000000000 -> queue_idx       0x0000000000000020 -> data_size
0xffff88801edfc408:     0x00000000000003f8 -> queue_size      0x0000000000000028 -> max_entries
0xffff88801edfc418:     0xffff88801e3b4e60 -> queue->data
```

After this , queue entries follow - 

```sh
0xffff88801edfc420:     0x0000000000000001 -> idx      0xffff88801e3b4e40 -> data
0xffff88801edfc430:     0xffff88801edfc438 -> next     0x0000000000000002
0xffff88801edfc440:     0xffff88801e3b4e20             0xffff88801edfc450
0xffff88801edfc450:     0x0000000000000003             0xffff88801e3b4e00
0xffff88801edfc460:     0xffff88801edfc468             
...
```

2. **Delete Kqueue**

```c
static noinline long delete_kqueue(request_t request){  
    /* Check for out of bounds requests */              
    if(request.queue_idx>MAX_QUEUES)                    
        err("[-] Invalid idx");                         
                                                        
    /* Check for existence of the request kqueue */     
    queue *queue = kqueues[request.queue_idx];          
    if(!queue)                                          
        err("[-] Requested kqueue does not exist");     
                                                        
    memset(queue,0,queue->queue_size);                  
    kfree(queue);                                       
    kqueues[request.queue_idx] = NULL;                  
    return 0;                                           
}                                                       
```

+ This function just frees the kqueue and nulls out it's memory.

3. **Edit Kqueue**

```c
static noinline long edit_kqueue(request_t request){
    /* Check the idx of the kqueue */                                              
    if(request.queue_idx > MAX_QUEUES)                                             
        err("[-] Invalid kqueue idx");                                             
                                                                                   
    /* Check if the kqueue exists at that idx */                                   
    queue *queue = kqueues[request.queue_idx];                                     
    if(!queue)                                                                     
        err("[-] kqueue does not exist");                                          
                                                                                   
    /* Check the idx of the kqueue entry */                                        
    if(request.entry_idx > queue->max_entries)                                     
        err("[-] Invalid kqueue entry_idx");                                       
                                                                                   
    /* Get to the kqueue entry memory */                                           
    queue_entry *kqueue_entry = (queue_entry *)(queue + (sizeof(queue)+1)/8);      
                                                                                   
    /* Check for the existence of the kqueue entry */                              
    exists = false;                                                                
    uint32_t i=1;                                                                  
    for(i=1;i<queue->max_entries+1;i++){                                           
                                                                                   
        /* If kqueue entry found , do the necessary */                             
        if(kqueue_entry && request.data && queue->data_size){                      
            if(kqueue_entry->idx == request.entry_idx){                            
                validate(memcpy(kqueue_entry->data,request.data,queue->data_size));
                exists = true;                                                     
            }                                                                      
        }                                                                          
        kqueue_entry = kqueue_entry->next;                                         
    }                                                                              
                                                                                   
    /* What if the idx is 0, it means we have to update the main kqueue's data */  
    if(request.entry_idx==0 && kqueue_entry && request.data && queue->data_size){  
        validate(memcpy(queue->data,request.data,queue->data_size));               
        return 0;                                                                  
```

+ This function basically iterates through the entries of the requested queue and copies `request.data` into `kqueue_entry->data`.

4. **Save Kqueue**

```c
/* Now you have the option to safely preserve your precious kqueues */         
static noinline long save_kqueue_entries(request_t request){                   
                                                                               
    /* Check for out of bounds queue_idx requests */                           
    if(request.queue_idx > MAX_QUEUES)                                         
        err("[-] Invalid kqueue idx");                                         
                                                                               
    /* Check if queue is already saved or not */                               
    if(isSaved[request.queue_idx]==true)                                       
        err("[-] Queue already saved");                                        
                                                                               
    queue *queue = validate(kqueues[request.queue_idx]);                       
                                                                               
    /* Check if number of requested entries exceed the existing entries */     
    if(request.max_entries < 1 || request.max_entries > queue->max_entries)    
        err("[-] Invalid entry count");                                        
```

Basic checks which ensure no out of bound access. We also check if `request.max_entries` are greater than `queue->max_entries`.

```c

    /* Each saved entry can have its own size */                                 
    if(request.data_size > queue->queue_size)                                     
        err("[-] Entry size limit exceed"); 

    /* Allocate memory for the kqueue to be saved */                             
    char *new_queue = validate((char *)kzalloc(queue->queue_size,GFP_KERNEL);                                  


    /* Copy main's queue's data */                                               
    if(queue->data && request.data_size)                                         
        validate(memcpy(new_queue,queue->data,request.data_size));               
    else                                                                         
        err("[-] Internal error");                                               
    new_queue += queue->data_size;                                               
```

+ Here , `request.data_size` is checked against `queue->queue_size` which obviously paves a straight away path for a heap overflow.

`request.data_size` can be large enough and eventually , the memory allocated for the `max_entries` will overflow into the next chunk.

**Note** - This was actually unintended on my part, the proper way of exploiting the challenge was through abusing the integer overflow which I will nevertheless discuss about in a moment.

+ `kzalloc` is called to allocate memory for the new queue.
+ First , data of main queue is copied to the new queue.
+ Subsequently, we iterate through max_entries and copy data of other entries as well.

```c
    /* copy all possible kqueue entries */                                    
    uint32_t i=0;                                                             
    for(i=1;i<request.max_entries+1;i++){                                     
        if(!kqueue_entry || !kqueue_entry->data)                              
            break;                                                            
        if(kqueue_entry->data && request.data_size)                           
            validate(memcpy(new_queue,kqueue_entry->data,request.data_size)); 
        else                                                                  
            err("[-] Internal error");                                        
        kqueue_entry = kqueue_entry->next;                                    
        new_queue += queue->data_size;                                        
    }                                                                         
                                                                              
    /* Mark the queue as saved */                                             
    isSaved[request.queue_idx] = true;                                        
    return 0;                                                                 
}                                                                             
```

Finally , we mark the queue as saved , note that a saved queue cannot be saved again.

## Idea of exploitation

```c
    if(__builtin_umulll_overflow(sizeof(queue_entry),(request.max_entries+1),&space) == true)                                                                         
```

Since there's no check on `request.max_entries`, a `0xffffffff` as max_entries results in integer overflow. This when coupled with the save option can result in a heap overflow.

With the heap overflow , since smep is disabled, we can overwrite it with pointer to userspace shellcode. There is no need of leaks since we have shellcode execution , we can easily control some register which already points to a kernel code address and change it to point to any function we wish to call in kernel.


## Conclusion

The challenge could have been made better by enabling smep and smap , it would have been more fun to leak kernel pointers with partial overwrites but yes , the exploit would have been a lot less reliable in that case. 

[Here](https://gist.github.com/PwnVerse/88d078653bb810759d86564dbc2258a6) is the complete exploit.

Flag - `inctf{l3akl3ss_r1p_w1th_u5erSp4ce_7rick3ry}`

