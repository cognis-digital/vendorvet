/*
 * vendorvet/polyglot/c/questionnaire_builder.c
 * 
 * Questionnaire builder for third-party/vendor risk questionnaires
 * with SBOM (Software Bill of Materials) cross-reference capability.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_SECTIONS 256
#define MAX_QUESTIONS 4096
#define MAX_SBO