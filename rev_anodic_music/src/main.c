#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define FLAG_LEN 62
#define DIALOGUES 16

char* dialogue [DIALOGUES]= {
    "HARDCORE!\n",
    "HARDCORE TO THE MEGA!\n",
    "HAAAAARD COOOOORE!\n",
    "Internally Coherent!\n",
    "YEEEEEEEEEEAHHHHHHHH!\n",
    "Is it though?\n",
    "The question is, what is the question?\n",
    "HARD CORE! ALL RIGHT! YEAH!\n",
    "SO HARD CORE!\n",
    "But is it? I mean, really?\n",
    "Good morning yeah! One two three! Yekokata, the place to be!\n",
    "CRAB MAN!\n",
    "Lakierski Materialski!\n",
    "LOVE IS HARDCORE!\n",
    "Spinning out lyrics since the day I was born!\n",
    "And the amount of lyrics I got is against the law!\n",
};

struct md5_hash {
    unsigned char data[16];
};

struct bank {
    long int len;
    struct md5_hash* list_start;
};

struct bank* load_bank() {
    FILE *fileptr;
    struct md5_hash *buffer;
    long filelen;
    // Shamelessly copied from stackoverflow, as any good security-aware developer should do. 
    // Jokes aside, this isn't meant to be vulnerable. If it is, send me a ping (but it doesn't matter since the challenge is fully local)
    fileptr = fopen("hardcore.bnk", "rb");  // Open the file in binary mode
    fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
    filelen = ftell(fileptr);             // Get the current byte offset in the file
    rewind(fileptr);                      // Jump back to the beginning of the file
    //printf("DEBUG: loading bank, filesize:%ld\n", filelen);

    buffer = (struct md5_hash *)malloc(filelen * sizeof(unsigned char)); // Enough memory for the file
    fread(buffer, filelen, 1, fileptr); // Read in the entire file
    fclose(fileptr); // Close the file

    struct bank* res = (struct bank*)malloc(sizeof(struct bank));
    res->len = filelen;
    res->list_start = buffer;

    //printf("DEBUG: loaded bank at %p. Len %ld, first hash half %08X\n", res, res->len, *res->list_start);

    return res;
}

bool lookup_bank(struct md5_hash* to_check, struct bank* b) {
    for (long long int i = 0; i < (b->len/16); i++) {
        //printf("DEBUG: checking %p against %p, offset %lld, max len %ld\n", to_check, b->list_start+i, i, b->len);
        if (!memcmp(to_check, b->list_start + i, 16)) {
            return true;
        }
    }
    return false;
}

char* get_dialogue(){
    FILE *ur;
    ur = fopen("/dev/urandom", "rb");

    unsigned char rb;
    fread(&rb, 1, sizeof(unsigned char), ur);
    return dialogue[rb%DIALOGUES];
}

int main()
{
    char flagbuf[FLAG_LEN] = {0,};
    struct md5_hash* tmp_hash = (struct md5_hash*) malloc(sizeof(struct md5_hash));
    struct bank* b = load_bank();

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    
    for(int i = 0; i < FLAG_LEN; i++) {
        printf("%s", get_dialogue());
        flagbuf[i] = getc(stdin);
        getc(stdin); // Strip enter
        md5String(flagbuf, tmp_hash);  
        if (feof(stdin) || lookup_bank(tmp_hash, b)) { // Bank hit = FAIL
            printf("There has to be some way to talk to this person, you just haven't found it yet.\n");
            return -1;
        }
    }
    printf("Hey it looks like you have input the right flag. Why are you still here?");

    return 0;
}