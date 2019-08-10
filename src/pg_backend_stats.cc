extern "C" {
#include "postgres.h"

#include <ctype.h>
#include <limits.h>

#include "commands/explain.h"
#include "executor/instrument.h"
#include "utils/guc.h"
#include "funcapi.h"
#include "miscadmin.h"

}

extern "C" {

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(pg_backend_stats_last_query);

static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;

void		_PG_init(void);
void		_PG_fini(void);

static void pg_backend_ExecutorStart(QueryDesc *queryDesc, int eflags);
static void pg_backend_ExecutorEnd(QueryDesc *queryDesc);

typedef struct io_stats
{
	unsigned long read_bytes;
	unsigned long write_bytes;
} io_stats;

int pg_backend_stats_read_actual_io(io_stats *ios);

static bool pg_backend_stats_enabled = false;

static BufferUsage prevQuery{};
static io_stats prevQueryIo, curQueryStart;

}

Datum
pg_backend_stats_last_query(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;

	/* check to see if caller supports us returning a tuplestore */
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not " \
						"allowed in this context")));

	/* Switch into long-lived context to construct returned data structures */
	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	/* Build a tuple descriptor for our result type */
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	Datum		values[14];
	bool		nulls[14];
	int			i = 0;

	memset(values, 0, sizeof(values));
	memset(nulls, 0, sizeof(nulls));

	values[i++] = Int64GetDatum(prevQuery.shared_blks_hit);
	values[i++] = Int64GetDatum(prevQuery.shared_blks_read);
	values[i++] = Int64GetDatum(prevQuery.shared_blks_dirtied);
	values[i++] = Int64GetDatum(prevQuery.shared_blks_written);
	values[i++] = Int64GetDatum(INSTR_TIME_GET_MILLISEC(prevQuery.blk_read_time));
	values[i++] = Int64GetDatum(INSTR_TIME_GET_MILLISEC(prevQuery.blk_write_time));
	values[i++] = Int64GetDatum(prevQuery.temp_blks_read);
	values[i++] = Int64GetDatum(prevQuery.temp_blks_written);
	values[i++] = Int64GetDatum(prevQuery.local_blks_hit);
	values[i++] = Int64GetDatum(prevQuery.local_blks_read);
	values[i++] = Int64GetDatum(prevQuery.local_blks_dirtied);
	values[i++] = Int64GetDatum(prevQuery.local_blks_written);
	long read_blocks = prevQueryIo.read_bytes / BLCKSZ;
	long write_blocks = prevQueryIo.write_bytes / BLCKSZ;
	values[i++] = Int64GetDatum(read_blocks);
	values[i++] = Int64GetDatum(write_blocks);

	tuplestore_putvalues(tupstore, tupdesc, values, nulls);

	tuplestore_donestoring(tupstore);

	return Datum(0);
}

int pg_backend_stats_read_actual_io(io_stats *ios)
{
	FILE *fp;
	int i;

	/* Try to read given stat file */
	if ((fp = fopen("/proc/self/io", "r")) == NULL)
		return -1;

	i = fscanf(fp, "%*s%*s%*s%*s%*s%*s%*s%*s%*s %lu %*s %lu",
		   &ios->read_bytes, &ios->write_bytes);

	fclose(fp);

	return i == 2;
}

/*
 * Module load callback
 */
void
_PG_init(void)
{
	DefineCustomBoolVariable("pg_backend_stats.enabled",
							 "Enable collecting stats per backend",
							 NULL,
							 &pg_backend_stats_enabled,
							 false,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);


	EmitWarningsOnPlaceholders("pg_backend_stats");

	/* Install hooks. */
	prev_ExecutorStart = ExecutorStart_hook;
	ExecutorStart_hook = pg_backend_ExecutorStart;
	prev_ExecutorEnd = ExecutorEnd_hook;
	ExecutorEnd_hook = pg_backend_ExecutorEnd;
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Uninstall hooks. */
	ExecutorStart_hook = prev_ExecutorStart;
	ExecutorEnd_hook = prev_ExecutorEnd;
}

/*
 * ExecutorStart hook: start up logging if needed
 */
static void
pg_backend_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
	if (pg_backend_stats_enabled && (eflags & EXEC_FLAG_EXPLAIN_ONLY) == 0)
	{
		queryDesc->instrument_options |= INSTRUMENT_BUFFERS;
	}

	if (prev_ExecutorStart)
		prev_ExecutorStart(queryDesc, eflags);
	else
		standard_ExecutorStart(queryDesc, eflags);

	if (pg_backend_stats_enabled)
	{
		/*
		 * Set up to track total elapsed time in ExecutorRun.  Make sure the
		 * space is allocated in the per-query context so it will go away at
		 * ExecutorEnd.
		 */
		if (queryDesc->totaltime == NULL)
		{
			MemoryContext oldcxt;

			oldcxt = MemoryContextSwitchTo(queryDesc->estate->es_query_cxt);
			queryDesc->totaltime = InstrAlloc(1, INSTRUMENT_BUFFERS);
			MemoryContextSwitchTo(oldcxt);
		}

		pg_backend_stats_read_actual_io(&curQueryStart);
	}
}

/*
 * ExecutorEnd hook: log results if needed
 */
static void
pg_backend_ExecutorEnd(QueryDesc *queryDesc)
{
	if (queryDesc->totaltime && pg_backend_stats_enabled)
	{
		/*
		 * Make sure stats accumulation is done.  (Note: it's okay if several
		 * levels of hook all do this.)
		 */
		InstrEndLoop(queryDesc->totaltime);

		memcpy(&prevQuery, &queryDesc->totaltime->bufusage, sizeof(BufferUsage));

		io_stats curQueryEnd{};
		if (pg_backend_stats_read_actual_io(&curQueryEnd))
		{
			prevQueryIo.read_bytes = curQueryEnd.read_bytes - curQueryStart.read_bytes;
			prevQueryIo.write_bytes = curQueryEnd.write_bytes - curQueryStart.write_bytes;
		}
		else
		{
			prevQueryIo.read_bytes = 0;
			prevQueryIo.write_bytes = 0;
		}
	}

	if (prev_ExecutorEnd)
		prev_ExecutorEnd(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}
