#include "stdio.h"
#include "stdlib.h"
#include "time.h"
#include "string.h"

/* Include the cryto-algorithms here */
#include "aes.h"
#include "arcfour.h"
#include "base64.h"
#include "blowfish.h"
#include "des.h"
#include "md2.h"
#include "md5.h"
#include "rot-13.h"
#include "sha1.h"
#include "sha256.h"

double diff_in_second(struct timespec t1, struct timespec t2);
void des_test();


int main(int argc, char* argv[]) {
	struct timespec start, end;
	clock_gettime(CLOCK_REALTIME, &start);
	// write test function here
	des_test();

	clock_gettime(CLOCK_REALTIME, &end);

	printf("elapsed time: %.9lf\n", diff_in_second(start, end));

	return 0;
}


double diff_in_second(struct timespec t1, struct timespec t2)
{
	struct timespec diff;
	if (t2.tv_nsec - t1.tv_nsec < 0) {
		diff.tv_sec  = t2.tv_sec - t1.tv_sec - 1;
		diff.tv_nsec = t2.tv_nsec - t1.tv_nsec + 1000000000;
	} else {
		diff.tv_sec  = t2.tv_sec - t1.tv_sec;
		diff.tv_nsec = t2.tv_nsec - t1.tv_nsec;
	}
	return (diff.tv_sec + diff.tv_nsec / 1000000000.0);
}

void des_test()
{
	BYTE pt1[DES_BLOCK_SIZE] = "ABCDEFG";
	BYTE key1[DES_BLOCK_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};

	BYTE schedule[16][6];
	BYTE buf[DES_BLOCK_SIZE];
	int pass = 1;

	des_key_setup(key1, schedule, DES_ENCRYPT);
	printf("\n-------- Before DES -------\n");
	for(int i = 0; i<= strlen(pt1)-1; i++)
		printf("%02x ",pt1[i]);
	des_crypt(pt1, buf, schedule);
	printf("\n-------- After DES --------\n");
	for(int i = 0; i<= strlen(buf)-1; i++)
		printf("%02x ",buf[i]);

	printf("\n---------------------------\n");

}