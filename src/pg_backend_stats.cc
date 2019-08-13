#include <functional>

extern "C" {
#include "postgres.h"

#include <ctype.h>
#include <limits.h>

#include "commands/explain.h"
#include "executor/instrument.h"
#include "utils/guc.h"
#include "utils/builtins.h"
#include "funcapi.h"
#include "miscadmin.h"

#include "parser/parser.h"
#include "nodes/nodes.h"
#include "nodes/nodeFuncs.h"
#include "nodes/parsenodes.h"
}

extern "C" {

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(pg_backend_stats_last_query);
PG_FUNCTION_INFO_V1(pg_compute_query_id);

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

typedef struct id_state
{
	unsigned long id;
} id_state;

int pg_backend_stats_read_actual_io(io_stats *ios);

static bool pg_backend_stats_enabled = false;

static BufferUsage prevQuery{};
static io_stats prevQueryIo, curQueryStart;

}

namespace {
template <class T>
inline void hash_combine(std::size_t& seed, const T& v)
{
	std::hash<T> hasher;
	seed ^= hasher(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
}
}

static bool
function_call_walker(Node *node, void *context)
{
	if (node == NULL)
		return false;

	id_state* state = (id_state*)context;

	if (nodeTag(node) != T_Const && nodeTag(node) != T_Param && nodeTag(node) != T_A_Const && nodeTag(node) != T_ParamRef &&
			nodeTag(node) != T_Alias)
		hash_combine(state->id, node->type);

	switch (nodeTag(node))
	{
		case T_Var:
			{
			}
			break;
		case T_Const:
			{
			}
			break;
		case T_Param:
			{
			}
			break;
		case T_Aggref:
			{
			}
			break;
		case T_GroupingFunc:
			{
			}
			break;
		case T_WindowFunc:
			{
			}
			break;
		case T_ArrayRef:
			{
			}
			break;
		case T_FuncExpr:
			{

			}
			break;
		case T_NamedArgExpr:
			{
				NamedArgExpr *nae = (NamedArgExpr *) node;
				//hash_combine(state->id, node->type);
				hash_combine(state->id, std::string(nae->name));
			}
			break;
		case T_OpExpr:
		case T_DistinctExpr:	/* struct-equivalent to OpExpr */
		case T_NullIfExpr:		/* struct-equivalent to OpExpr */
			{
			}
			break;
		case T_ScalarArrayOpExpr:
			{
			}
			break;
		case T_BoolExpr:
			{
				BoolExpr   *expr = (BoolExpr *) node;
				//hash_combine(state->id, node->type);
				hash_combine(state->id, expr->boolop);
			}
			break;
		case T_SubLink:
			{

			}
			break;
		case T_FieldSelect:
			{

			}
			break;
		case T_FieldStore:
			{

			}
			break;
		case T_RelabelType:
			{

			}
			break;
		case T_CoerceViaIO:
			{

			}
			break;
		case T_ArrayCoerceExpr:
			{

			}
			break;
		case T_ConvertRowtypeExpr:
			{

			}
			break;
		case T_CollateExpr:
			{

			}
			break;
		case T_CaseExpr:
			{

			}
			break;
		case T_CaseTestExpr:
			{

			}
			break;
		case T_ArrayExpr:

			break;
		case T_RowExpr:

			break;
		case T_RowCompareExpr:
			{

			}
			break;
		case T_CoalesceExpr:

			break;
		case T_MinMaxExpr:
			{

			}
			break;
		case T_SQLValueFunction:
			{

			}
			break;
		case T_XmlExpr:
			{

			}
			break;
		case T_NullTest:
			{

			}
			break;
		case T_BooleanTest:
			{

			}
			break;
		case T_CoerceToDomain:
			{

			}
			break;
		case T_CoerceToDomainValue:
			{

			}
			break;
		case T_SetToDefault:
			{

			}
			break;
		case T_CurrentOfExpr:
			{

			}
			break;
		case T_NextValueExpr:
			{

			}
			break;
		case T_InferenceElem:
			{

			}
			break;
		case T_TargetEntry:
			{

			}
			break;
		case T_RangeTblRef:
			{

			}
			break;
		case T_JoinExpr:
			{

			}
			break;
		case T_FromExpr:
			{

			}
			break;
		case T_OnConflictExpr:
			{

			}
			break;
		case T_List:

			break;
		case T_IntList:

			break;
		case T_SortGroupClause:
			{

			}
			break;
		case T_GroupingSet:
			{

			}
			break;
		case T_WindowClause:
			{

			}
			break;
		case T_CommonTableExpr:
			{

			}
			break;
		case T_SetOperationStmt:
			{

			}
			break;
		case T_RangeTblFunction:
			{

			}
			break;
		case T_TableFunc:
			{

			}
			break;
		case T_TableSampleClause:
			{

			}
			break;
		case T_ResTarget:
			{
				ResTarget* tgt = (ResTarget*)node;
				if (tgt->name)
				{
					//hash_combine(state->id, node->type);
					hash_combine(state->id, std::string(tgt->name));
				}
			}
			break;
		case T_ColumnRef:
			{
				ColumnRef* ref = (ColumnRef*)node;
				ListCell* c;
				foreach(c, ref->fields)
				{
					Node	   *n = (Node *) lfirst(c);

					if (IsA(n, String))
					{
						Value	   *v = (Value *) lfirst(c);
						hash_combine(state->id, std::string(v->val.str));
					}
					else if (IsA(n, A_Star))
					{
						hash_combine(state->id, '*');
					}
				}
			}
			break;
		case T_RangeVar:
			{
				RangeVar* ref = (RangeVar*)node;
				//hash_combine(state->id, node->type);
				if (ref->catalogname)
					hash_combine(state->id, std::string(ref->catalogname));
				if (ref->schemaname)
					hash_combine(state->id, std::string(ref->schemaname));
				hash_combine(state->id, std::string(ref->relname));
			}
			break;
		case T_A_Const:
			break;
		case T_FuncCall:
			{
				FuncCall *fnc = (FuncCall*)node;

				ListCell   *lc;
				Value	   *v;

				foreach(lc, fnc->funcname)
				{
					v = (Value *) lfirst(lc);

					if (IsA(v, String))
					{
						hash_combine(state->id, std::string(v->val.str));
					}
				}
			}
			break;
		case T_RangeFunction:
			break;
		case T_TypeCast:
			break;
		case T_TypeName:
		{
			TypeName* name = (TypeName*)node;

			ListCell   *lc;
			Value	   *v;

			foreach(lc, name->names)
			{
				v = (Value *) lfirst(lc);

				if (IsA(v, String))
				{
					hash_combine(state->id, std::string(v->val.str));
				}
			}
		}
		break;
		case T_SelectStmt:
		{
			SelectStmt* sel = (SelectStmt*)node;
			hash_combine(state->id, sel->op);
			hash_combine(state->id, sel->larg == NULL);
			hash_combine(state->id, sel->intoClause == NULL);
			hash_combine(state->id, sel->fromClause == NULL);
			hash_combine(state->id, sel->limitCount == NULL);
			hash_combine(state->id, sel->sortClause == NULL);
			hash_combine(state->id, sel->withClause == NULL);
			hash_combine(state->id, sel->groupClause == NULL);
			hash_combine(state->id, sel->limitOffset == NULL);
			hash_combine(state->id, sel->whereClause == NULL);
			hash_combine(state->id, sel->havingClause == NULL);
			hash_combine(state->id, sel->windowClause == NULL);
			hash_combine(state->id, sel->lockingClause == NULL);
			hash_combine(state->id, sel->distinctClause == NULL);

			if (sel->larg)
			{
				hash_combine(state->id, sel->all);
				hash_combine(state->id, sel->op);
			}
		}
			break;
		case T_Alias:
			break;
		case T_RangeSubselect:
			break;
		case T_ParamRef:
			break;
		case T_A_Expr:
			break;
		default:
			/* Only a warning, since we can stumble along anyway */
			//elog(WARNING, "unrecognized node type: %d",
			//	 (int) nodeTag(node));
			break;
	}

	return raw_expression_tree_walker(node, reinterpret_cast<bool(*)(void)>(function_call_walker), context);
}

Datum pg_compute_query_id(PG_FUNCTION_ARGS)
{
	char* ptr = text_to_cstring(PG_GETARG_TEXT_PP(0));
	id_state state{};
	bool returnNull = false;

	PG_TRY();
	{
		List* tree = raw_parser(ptr);
		Node *node = NULL;
		RawStmt *rstmt;
		rstmt = (RawStmt *) lfirst(list_head(tree));
		node = (Node *) rstmt->stmt;

		if (node->type == T_SelectStmt || node->type == T_InsertStmt || node->type == T_DeleteStmt || node->type == T_UpdateStmt)
			function_call_walker(node, &state);
		else
		{
			hash_combine(state.id, std::string(ptr));
		}

		pfree(tree);
		pfree(ptr);
	}
	PG_CATCH();
	{
		returnNull = true;
		FlushErrorState();
	}
	PG_END_TRY();

	if (returnNull)
	{
		PG_RETURN_NULL();
	}
	else
	{
		return DatumGetInt64(state.id);
	}

	//elog(INFO, "%s", nodeToString(node));

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
