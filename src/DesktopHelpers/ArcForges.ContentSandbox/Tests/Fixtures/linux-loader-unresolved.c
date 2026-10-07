/* SPDX-License-Identifier: AGPL-3.0-only */
/* RTLD_LAZY would admit this handle; RTLD_NOW must refuse before use. */
extern int arc_loader_missing_dependency(void);
int arc_loader_answer(void) { return arc_loader_missing_dependency(); }
