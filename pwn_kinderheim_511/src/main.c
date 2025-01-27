#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


#define MAX_MEMORIES 16
#define MAX_MEM_LEN 64


int collect_num(bool safe, int max) {
    int res;
    printf("Select the number you require.\n");
    scanf("%d", &res);
    getchar();
    if (safe && (res == 0 || res >= max)){
        printf("You cannot select that.\n");
        exit(0);
    }
    return res;
}

void add_mem_to_record(char** record, char* memory){
    char* cur_ptr;
    for  (int idx = 0; idx < MAX_MEMORIES; idx++) {
        cur_ptr = record[idx];
        if (cur_ptr == NULL) {
            record[idx] = memory;
            printf("Memorized in slot %d.\n", idx);
            return;
        }
    }
    printf("Ran out of memory.\n");
}

void recall_memory(char** record, int idx ) {
    char* cur_ptr;
    for  (int i = 0; i <= idx; i++) {
        cur_ptr = record[i];
        if (cur_ptr == NULL) {
            printf("There's a hole in your memory somewhere...\n");
            return;
        }
        else if (idx == i) {
            printf("Reading memory...\n\t\"%s\"", cur_ptr);
            return;
        }
    }
    printf("Ran out of memory.\n");
}

void erase_memory(char** record, int idx ) {
    char* cur_ptr = record;
    // Allows to leak libc if record hole is present during deletion, then filled. UAF
    // Also allows to free objects at negative indices, but this does not seem to be immediately exploitable. I'll keep it in beacuse it's funny.
    free(record[idx]); 

    for  (int i = 0; i <= idx; i++) {
        cur_ptr = record[i];
        if (cur_ptr == NULL) {
            printf("There's a hole in your memory somewhere...\n");
            return;
        }
        else if (idx == i) {
            record[i] = NULL;
            printf("Erased at slot %d", i);
            return;
        }
    }
    printf("Ran out of memory.\n");
}

void implant_user_memory(char** record){
    char* tempbuf[MAX_MEM_LEN];
    char* tempbuf2[MAX_MEM_LEN];
    printf("Input your memory (max %d chars).\n", MAX_MEM_LEN);
    fgets(tempbuf, MAX_MEM_LEN, stdin);

    int str_real_len = strnlen(tempbuf,MAX_MEM_LEN) -1; // This is correct, as fgets adds a null byte AFTER the enter, but we're doing the order wrong. Which means...
    printf("String collected. Len: %d\n", str_real_len);

    char* real_buf = malloc(sizeof(char)*str_real_len);
    strcpy(real_buf, tempbuf); // Bug: unbound write when we haven't zeroed the enter yet -> off-by-one write, which results in...
    if (real_buf[str_real_len] == "\n")
        real_buf[str_real_len] = NULL; // Bug: null byte poison to the following chunk for (chunk)+8 length strings
    
    add_mem_to_record(record, real_buf);
}


void implant_core_memory(char** record) {

    if(!getenv("FLAG")) {
        printf("Error reading flag env. If you see this in the CTF, call an admin.");
        exit(1);
    } else{        
        char* real_buf = malloc(sizeof(char)*MAX_MEM_LEN);        
        snprintf(real_buf, MAX_MEM_LEN, "%s", getenv("FLAG"));
        add_mem_to_record(record,real_buf);
        printf("Core memory created.\n");
    }
}



int main()
{
    char** record; // VERY IMPORTANT THAT THEYRE ALL NULLED
    int c;

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    record = calloc(MAX_MEMORIES, sizeof(char*));

    printf("People are such strange beings. The sad memories seem to just fade away, until all a person's left with are the happier ones.\n\n");
    // printf("While looking for the ancient Mayan treasure, we've found this: %8p\n\n", stdin); // Simplification for the libc variant

    implant_core_memory(record);

    while (true) {
        //printf("Debug info. Suggerisco di non usarle quando si sta creando l'exploit, ma fate come vi pare");
        //for (int i = 0; i < MAX_MEMORIES; i++){
        //    printf("\t%d: <%016X>\n", i, record[i]);
        //}
        printf("1) Create new memory\n2) Recollect memory\n3) Erase memory\n4) Quit.\n\n");
        scanf("%d", &c);
        getchar();
        if (c == 1) implant_user_memory(record);
        else if (c == 2) {
            int idx = collect_num(true, MAX_MEMORIES);
            recall_memory(record, idx);
        }
        else if (c == 3) {
            int idx = collect_num(true, MAX_MEMORIES);
            erase_memory(record, idx);
        }
        else if (c == 4) {
            printf("What exactly is the end? The end. The end. The end. I've seen the end over and over. What is the end?\n");
            return 0;
        }
        else printf("Sorry, try again.\n");
    }  

    return 0;
}