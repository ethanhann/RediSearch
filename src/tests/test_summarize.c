#include "test_util.h"
#include "fragmenter.h"
#include <stdio.h>
#include "../rmutil/alloc.h"

char *LoremIpsum_g;
#define LOREM_IPSUM_FILE "./lorem_ipsum.txt"
char *getLoremIpsum() {
  if (LoremIpsum_g) {
    return strdup(LoremIpsum_g);
  }

  FILE *fp = fopen(LOREM_IPSUM_FILE, "r");
  if (fp == NULL) {
    perror(LOREM_IPSUM_FILE);
    abort();
  }
  fseek(fp, 0, SEEK_END);
  size_t nbuf = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  if (nbuf == 0) {
    fprintf(stderr, "File is empty!\n");
    abort();
  }

  LoremIpsum_g = malloc(nbuf + 1);
  LoremIpsum_g[nbuf] = '\0';
  for (size_t nr = 0; nr < nbuf; nr = fread(LoremIpsum_g + nr, 1, 4096, fp)) {
  }
  fclose(fp);

  return getLoremIpsum();
}

#define SIMPLE_TERM(s) FRAGMENT_TERM(s, strlen(s), 1)
#define SCORED_TERM(s, score) FRAGMENT_TERM(s, strlen(s), score)

int testFragmentize() {
  char *lorem = getLoremIpsum();
  const FragmentTerm terms[] = {SIMPLE_TERM("dolor"), SCORED_TERM("ex", 0.4),
                                SIMPLE_TERM("magna"), SIMPLE_TERM("vitae"),
                                SIMPLE_TERM("sed"),   SCORED_TERM("et", 0.3)};
  size_t nterms = sizeof(terms) / sizeof(terms[0]);
  FragmentList fragList;
  FragmentList_Init(&fragList, terms, nterms, 8, 6);

  // Fragmentize
  FragmentList_Fragmentize(&fragList, lorem);
  size_t nfrags = FragmentList_GetNumFrags(&fragList);
  const Fragment *allFrags = FragmentList_GetFragments(&fragList);
  ASSERT(allFrags != NULL);
  ASSERT(nfrags != 0);
  printf("We have %lu frags\n", nfrags);
  printf("Text is %lu chars long\n", strlen(lorem));

  for (size_t ii = 0; ii < nfrags; ++ii) {
    const Fragment *cur = allFrags + ii;
    printf("Fragment (score=%f): <<<\n", cur->score);
    printf("%.*s\n", (int)cur->len, cur->buf);
    printf(">>>\n");
  }

  HighlightTags tags = {.openTag = "\033[1m", .closeTag = "\033[0m"};
  char *hlRes = FragmentList_HighlightWholeDocS(&fragList, &tags);
  printf("Highlighted: %s\n", hlRes);
  free(hlRes);
  free(lorem);

  FragmentList_Free(&fragList);
  return 0;
}

TEST_MAIN({

  // LOGGING_INIT(L_INFO);
  RMUTil_InitAlloc();
  TESTFUNC(testFragmentize);
});