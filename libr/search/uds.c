// https://github.com/quarkslab/binbloom/blob/master/binbloom.c

/* Copyright 2020 G. Heilles
 * Copyright 2020 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <r_list.h>
#include <r_util.h>
#include <r_search.h>

#define UDS_SIZE sizeof (UDS)
#define CANDB_SIZE 512


static unsigned char UDS[] = {
	0x10, 0x11, 0x27, 0x28, 0x3E, 0x83, 0x84, 0x85, 0x86, 0x87, 0x22, 0x23, 0x24, 0x2A, 0x2C, 0x2D, 0x2E, 0x3D, 0x14,
	0x19, 0x2F, 0x31, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x18, 0x3B, 0x20, 0x21, 0x1A
};

#if 0
static int is_unique_UDS(unsigned int position) {
    unsigned int j, flag;
    flag = 0;
    for (j = 0; j < UDS_SIZE; j++) {
        if (firmware[position] == UDS[j]) {
            flag = 1;
            break;
        }
    }

    if (flag == 1) {
        for (j = position - CANDB_SIZE / 2; j < position + CANDB_SIZE / 2; j++) {
            if ((firmware[j] == firmware[position]) && (j != position)) {
                flag = 0;
                break;
            }
        }
    }
    return flag;
}
#endif

R_API RList *r_search_find_uds(RSearch *search, ut64 addr, const ut8 *data, size_t size, bool verbose) {
	RList *list = r_list_newf (free);
	if (size < (CANDB_SIZE * 2)) {
		eprintf ("requires at least 1024 bytes. %zd\n", size);
		return NULL;
	}
	unsigned int i, j, k, max_score, stride;
	unsigned int candb_position = 0;

	unsigned int *score = (unsigned int *)calloc (size, sizeof (int));
	unsigned int *stride_score = (unsigned int *)calloc (size, sizeof (int));

	unsigned char UDS_local[UDS_SIZE];
	for (i = 1; i < size - (CANDB_SIZE * 2); i++) {
		for (stride = 6; stride <= 32; stride += 2) {
			// prepare a local copy of the UDS service list, to remove them once each is found. This will ensure each UDS service is matched only once.
			memcpy(UDS_local, UDS, UDS_SIZE);
			max_score = 0;
			for (k = 0; k < CANDB_SIZE; k += stride) {
				bool flag = false;
				for (j = 0; j < UDS_SIZE; j++) {
					// printf("j=%d, k=%d ", j, k);
					if ((data[i + k] == UDS_local[j]) && (UDS_local[j] != 0)) {
						//printf("at %#08x + %#08x, data=%#02x (j=%d, stride=%d)\n", i, k, data[i+k], j, stride);
						max_score++;
						UDS_local[j] = 0;
						flag = true;
					}
				}
				if (!flag) {
					break;
				}
			}
			//  if (max_score) printf("Score at %#08x for stride %d: %d\n", i, stride, max_score);
			if (max_score > score[i]) {
				// printf("New high score for %#08x: %d\n", i, max_score);
				score[i] = max_score;
				stride_score[i] = stride;
			}
		}
	}

	// print 20 best candidates
	for (j = 0; j < 20; j++) {
		max_score = 0;
		unsigned int max_stride = 0;
		for (i = 0; i < size; i++) {
			if (score[i] > max_score) {
				max_score = score[i];
				max_stride = stride_score[i];
				candb_position = i;
			}
		}
		if (max_score == 0) {
			continue;
		}
		RSearchUds *uh = R_NEW0 (RSearchUds);
		if (!uh) {
			break;
		}
		uh->score = max_score;
		uh->stride = max_stride;
		uh->addr = addr + candb_position;
		r_list_append (list, uh);
		if (verbose) {
			eprintf ("UDS DB position: %x with a score of %d and a stride of %d:\n", candb_position, max_score, max_stride);
			unsigned int k;
			for (k = candb_position; k < candb_position + max_score * max_stride; k++) score[k] = 0; // skip all other references to this same candb
			for (i = 0; i < max_score; i++) {
				for (j = 0; j < max_stride; j++) {
					eprintf ("%02x ", data[candb_position + i * max_stride + j]);
				}
				eprintf ("\n");
			}
			eprintf ("\n");
		}
		score[candb_position] = 0;
	}
	free (score);
	free (stride_score);
	return list;
}
