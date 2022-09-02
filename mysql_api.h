#ifndef __MYSQL_API_H
#define __MYSQL_API_H
#include <mysql/mysql.h>

#define SQL_SUCCESS	0
#define SQL_FAILED	-1

#define SQL_DB	"audit_logs"

#define SQL_QUERY_SIZE	4096

#define SQL_FS \
	do { \
		*end++ = ','; \
	} while (0)

#define SQL_EOQ \
	do { \
		*end++ = ')'; \
		*end = '\0'; \
	} while (0)

#define SQL_COPY_N_ESCAPE_STRING(s) \
	do { \
		*end++ = '\''; \
		end += mysql_real_escape_string(handle, end, s, strlen(s)); \
		*end++ = '\''; \
	} while (0)

#define SQL_COPY_BINARY(s,n) \
	do { \
		int binary_offset; \
		*end++ = '\''; \
		if(n) \
		{ \
			len = sprintf(end, "0x"); \
			end += len; \
			for(binary_offset=0; binary_offset < n; binary_offset++) \
			{ \
				len = sprintf(end, "%02x",*(s + binary_offset)); \
				end += len; \
			} \
		} else \
		{ \
			len = sprintf(end, "NULL"); \
			end += len; \
		} \
		*end++ = '\''; \
	} while (0)

#define SQL_COPY_NULL_ESCAPE_STRING() \
	do { \
		*end++ = '\''; \
		*end++ = '\''; \
	} while (0)

#define SQL_COPY_NUMBER(n) \
	do { \
		*end++ = '\''; \
		len = sprintf(end, "%d", n); \
		end += len; \
		*end++ = '\''; \
	} while (0)

#define SQL_COPY_UNUMBER(n) \
	do { \
		*end++ = '\''; \
		len = sprintf(end, "%u", n); \
		end += len; \
		*end++ = '\''; \
	} while (0)

#define SQL_COPY_ULONG64(n) \
	do { \
		*end++ = '\''; \
		len = sprintf(end, "%llu", n); \
		end += len; \
		*end++ = '\''; \
	} while (0)

#define SQL_COPY_ULONG(n) \
	do { \
		*end++ = '\''; \
		len = sprintf(end, "%lu", n); \
		end += len; \
		*end++ = '\''; \
	} while (0)

#define SQL_COPY_FLOAT(n) \
	do { \
		*end++ = '\''; \
		len = sprintf(end, "%f", n); \
		end += len; \
		*end++ = '\''; \
	} while (0)

typedef MYSQL* sql_handle;

typedef struct {
	const char *table_name;
	const char *create_string;
	const char *insert_string;
	const char *drop_string;
	int (*sql_alter_table_handler)(sql_handle handle);
} sql_tables_t;

enum {
	AUDIT_MAIN_TABLE_INDEX,
	AUDIT_MODBUS_TABLE_INDEX,
	AUDIT_DNP3_TABLE_INDEX,
	AUDIT_TRDP_TABLE_INDEX,
	AUDIT_HTTP1_TABLE_INDEX,
	AUDIT_FTP_TABLE_INDEX,
	AUDIT_TELNET_TABLE_INDEX,
	STUDY_MODBUS_TABLE_INDEX,
	STUDY_DNP3_TABLE_INDEX,
	STUDY_TRDP_TABLE_INDEX,
};

int sql_database_init(void);
int sql_tables_init(const char *db_name);
sql_handle sql_db_connect(const char *db_name);
void sql_db_disconnect(sql_handle handle);
int sql_real_query(sql_handle handle, const char *qbuf, int len);

#endif
