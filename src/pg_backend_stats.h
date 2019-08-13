
#pragma once

extern "C" {

#include <ctype.h>
#include "fmgr.h"

}

extern "C" {

extern Datum pg_backend_stats_last_query(PG_FUNCTION_ARGS);
extern Datum pg_compute_query_id(PG_FUNCTION_ARGS);

}

