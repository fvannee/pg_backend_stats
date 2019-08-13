
create type pg_backend_stats as (
	shared_blks_hit bigint,
	shared_blks_read bigint,
	shared_blks_dirtied bigint,
	shared_blks_written bigint,
	blk_read_time bigint,
	blk_write_time bigint,
	temp_blks_read bigint,
	temp_blks_written bigint,
	local_blks_hit bigint,
	local_blks_read bigint,
	local_blks_dirtied bigint,
	local_blks_written bigint,
	actual_read_blocks bigint,
	actual_write_blocks bigint
);

CREATE OR REPLACE FUNCTION pg_backend_stats_last_query() RETURNS setof pg_backend_stats AS
'$libdir/pg_backend_stats'
LANGUAGE c STABLE STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION pg_compute_query_id(text) RETURNS bigint AS
'$libdir/pg_backend_stats'
LANGUAGE c STABLE STRICT PARALLEL SAFE;
